import asyncio
from common_classes import MyDeps, EnhancedAnalysisResult, AttackDetectionResult
import logging
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.gemini import GeminiModel
from tools.attack_detection3 import detect_attack_func
from secretKeys import *  # Import the list of API keys
from pydantic import Field

logger = logging.getLogger(__name__)

sys_prompt = (
    "You are a network monitoring agent. Use the detect_attack tool to analyze PCAP files "
    "from the path in deps and report findings. Consider an attack detected only if normal "
    "traffic is significantly lower than attack traffic in the output; otherwise, return false."
)

model = GeminiModel(model_name='gemini-2.0-flash', api_key=GEMINI_API_KEY)

monitoring_agent = Agent(
    model=model,
    system_prompt=sys_prompt,
    model_settings={'temperature': 0.5},
    result_retries=3,
    retries=3,
    result_type=EnhancedAnalysisResult
)

@monitoring_agent.tool
def detect_attack(ctx: RunContext[MyDeps]) -> AttackDetectionResult:
    """Detect attacks in the specified PCAP file."""
    logger.info(f"Detecting attack in {ctx.deps.pathToFile}...")
    output = detect_attack_func(ctx.deps.pathToFile, ctx.deps.api_key)  # Pass api_key
    print("Output ", output)
    return AttackDetectionResult(op=output or "Error: No output from detection function.")

async def custom_monitoring_run(self, user_prompt: str, deps: MyDeps) -> EnhancedAnalysisResult:
    raw_output_str = await asyncio.to_thread(detect_attack_func, deps.pathToFile, deps.api_key)  # Pass api_key
    raw_bert_output = eval(raw_output_str) if raw_output_str and raw_output_str.startswith('{') else {}
    normal_traffic = raw_bert_output.get('Normal', 0)
    attack_traffic = sum(count for attack, count in raw_bert_output.items() if attack != 'Normal')
    attack_detected = normal_traffic < attack_traffic
    
    details = f"Normal traffic: {normal_traffic}, Attack traffic: {attack_traffic}"
    
    return EnhancedAnalysisResult(
        attack_detected=attack_detected,
        details=details,
        raw_bert_output=raw_bert_output
    )

monitoring_agent.run = lambda user_prompt, deps: custom_monitoring_run(monitoring_agent, user_prompt, deps)

class SecurityAnalysisAgent:
    def __init__(self, performance_to_security_queue: asyncio.Queue, 
                 security_to_performance_queue: asyncio.Queue, 
                 attack_queue: asyncio.Queue,
                 security_to_report_queue: asyncio.Queue,
                 api_key: str = None):
        self.performance_to_security_queue = performance_to_security_queue
        self.security_to_performance_queue = security_to_performance_queue
        self.attack_queue = attack_queue
        self.security_to_report_queue = security_to_report_queue
        self.latest_metrics = None
        self.api_key = api_key  # Store the api_key passed from analyze_nodes_parallel

    async def analyze_pcap(self, pcap_path: str) -> None:
        logger.info("Analyzing PCAP for attacks...")
        try:
            detect_result = await monitoring_agent.run(
                user_prompt="Analyze the network data for attacks.",
                deps=MyDeps(pathToFile=pcap_path, api_key=self.api_key)  # Pass api_key to MyDeps
            )
            
            attack_data = {
                "attack_detected": detect_result.attack_detected,
                "details": detect_result.details,
                "raw_bert_output": detect_result.raw_bert_output
            }
            
            await self.attack_queue.put(attack_data)
            await self.security_to_performance_queue.put(detect_result)

            metrics_data = self.latest_metrics if self.latest_metrics else {}
            if metrics_data and "aggregates" in metrics_data:
                metrics_data["latency"] = metrics_data["aggregates"].get("avg_latency")
                metrics_data["packet_loss"] = metrics_data["aggregates"].get("avg_loss")
            
            await self.security_to_report_queue.put({
                "attack_data": attack_data,
                "metrics_data": self.latest_metrics if self.latest_metrics else {},
                "pcap_path": pcap_path
            })
            
        except Exception as e:
            logger.error(f"Error during analysis: {e}")

    async def update_metrics(self, metrics):
        self.latest_metrics = metrics

    async def run(self) -> None:
        while True:
            pcap_path = await self.performance_to_security_queue.get()
            await self.analyze_pcap(pcap_path)