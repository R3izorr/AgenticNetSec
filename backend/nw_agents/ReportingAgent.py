import logging
import asyncio
from collections import deque
logger = logging.getLogger(__name__)

from pydantic_ai import Agent, RunContext
from pydantic_ai.models.gemini import GeminiModel
from common_classes import NetworkReport, MyDeps, AnalysisResult
from secretKeys import GEMINI_API_KEY
from tools.pcap_analyzer import analyze_pcap_summary
import uuid
import time

sys_prompt = """
You are a network analysis reporting agent. Generate comprehensive reports on network anomalies 
and security incidents using attack detection data and raw BERT model output. For each report:

1. Analyze attack data, raw BERT model output (attack type counts), and network metrics to identify patterns and anomalies
2. Determine the type and severity of any detected attacks based on BERT classifications
3. Recommend specific mitigation actions with clear priorities, tailored to identified attack types
4. Suggest further investigation steps when appropriate
5. Create concise but thorough summaries suitable for both technical and non-technical readers

Be specific and actionable in your recommendations. Include command suggestions when appropriate.
Include a confidence level based on the clarity of the evidence and the volume of attack traffic in the BERT output.
"""

model = GeminiModel(model_name='gemini-2.0-flash', api_key=GEMINI_API_KEY)

reporting_agent = Agent(
    model=model,
    system_prompt=sys_prompt,
    model_settings={'temperature': 0.2},
    result_retries=3,
    retries=3,
    result_type=NetworkReport
)

@reporting_agent.tool
def get_pcap_summary(ctx: RunContext[MyDeps]) -> dict:
    print(f"Analyzing {ctx.deps.pathToFile}")
    summary = analyze_pcap_summary(ctx.deps.pathToFile)
    return summary

@reporting_agent.tool
def generate_report_id(ctx: RunContext[MyDeps]) -> str:
    return f"NR-{uuid.uuid4().hex[:8]}-{int(time.time())}"

@reporting_agent.tool
def format_timestamp(ctx: RunContext[MyDeps]) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")

@reporting_agent.tool
def get_network_metrics(ctx: RunContext[MyDeps]) -> dict:
    return {
        "latency": ctx.deps.avg_latency if ctx.deps.avg_latency is not None else 0.0,
        "packet_loss": ctx.deps.avg_loss if ctx.deps.avg_loss is not None else 0.0,
        "duration": ctx.deps.duration,
        "interval": ctx.deps.cycle_interval
    }

async def generate_network_report(analysis_result: AnalysisResult, pcap_path: str, 
                                 duration: int, cycle_interval: int, 
                                 avg_latency: float = None, avg_loss: float = None) -> NetworkReport:
    deps = MyDeps(
        pathToFile=pcap_path,
        duration=duration,
        cycle_interval=cycle_interval,
        avg_latency=avg_latency,
        avg_loss=avg_loss
    )
    
    try:
        raw_bert_output = analysis_result.get('raw_bert_output', {}) if isinstance(analysis_result, dict) else getattr(analysis_result, 'raw_bert_output', {})
        prompt = (
            f"Generate a comprehensive report based on the following data:\n"
            f"- Attack detection result: {analysis_result['attack_detected'] if isinstance(analysis_result, dict) else analysis_result.attack_detected}\n"
            f"- Detection details: {analysis_result['details'] if isinstance(analysis_result, dict) else analysis_result.details}\n"
            f"- Raw BERT model output (attack type counts): {raw_bert_output}\n"
            f"- Network metrics: Latency={avg_latency}ms, Loss={avg_loss}%, Duration={duration}s, Interval={cycle_interval}s\n"
            f"Use the raw BERT output to identify specific attack types and their severity."
        )
        
        result = await reporting_agent.run(user_prompt=prompt, deps=deps)
        return result.data  # Extract the NetworkReport from RunResult
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return NetworkReport(
            report_id=f"NR-ERROR-{int(time.time())}",
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            summary=f"Report generation failed: {str(e)}",
            attack_detected=analysis_result['attack_detected'] if isinstance(analysis_result, dict) else analysis_result.attack_detected,
            attack_type=None,
            confidence=0.0,
            metrics_summary=f"Latency: {avg_latency}ms, Loss: {avg_loss}%",
            anomalies_detected="Error in analysis",
            potential_causes="Unknown due to error",
            recommended_actions="Please retry analysis",
            further_investigation="Investigate report generation failure"
        )

class ReportingAgent:
    def __init__(self, security_to_reporting_queue: asyncio.Queue, reports_queue: asyncio.Queue):
        self.security_to_reporting_queue = security_to_reporting_queue
        self.reports_queue = reports_queue
        self.metrics_history = deque(maxlen=50)

    async def generate_report(self, attack_data, metrics_data, pcap_path):
        """Generate comprehensive report about detected anomalies and recommended actions."""
        logger.info("Generating network analysis report...")
        await asyncio.sleep(15)
        try:
            report_result = await generate_network_report(
                analysis_result=attack_data,  # Now includes raw_bert_output
                pcap_path=pcap_path,
                duration=metrics_data.get("duration", 5),
                cycle_interval=metrics_data.get("interval", 2),
                avg_latency=metrics_data.get("latency"),
                avg_loss=metrics_data.get("packet_loss")
            )
            await self.reports_queue.put(report_result)
            logger.info(f"Report generated: {report_result.report_id}")
            return report_result
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None

    async def update_metrics_history(self, metrics):
        """Store metrics history for trend analysis in reports."""
        self.metrics_history.append(metrics)

    async def run(self):
        """Process security analysis results and generate reports."""
        while True:
            data = await self.security_to_reporting_queue.get()
            attack_data = data["attack_data"]
            metrics_data = data["metrics_data"]
            pcap_path = data["pcap_path"]
            await self.generate_report(attack_data, metrics_data, pcap_path)