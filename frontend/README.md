# Frontend (Next.js + React + Tailwind)

This frontend is scaffolded with Next.js App Router, TypeScript, React, and Tailwind CSS.

## Stack

- Next.js 16 (App Router)
- React 19
- TypeScript
- Tailwind CSS 4
- ESLint

## Setup

From repository root:

```bash
cd frontend
npm install
```

## Run

```bash
npm run dev
```

Open `http://localhost:3000`.

## Build and Lint

```bash
npm run lint
npm run build
npm run start
```

## Environment Variables

Copy values from `.env.example` into your local `.env.local` if needed:

- `NEXT_PUBLIC_API_BASE_URL`
- `NEXT_PUBLIC_WS_URL`

## Structure

- `app/layout.tsx`: shell layout and top navigation
- `app/page.tsx`: starter dashboard view
- `app/globals.css`: global styles and theme tokens
- `public/`: static assets
