import asyncio

from app.db import init_db
from app.jobs import fetch_next_pending_job, run_collect_job


async def main() -> None:
    init_db()
    while True:
        job = fetch_next_pending_job()
        if job:
            await run_collect_job(int(job["id"]))
        else:
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(main())
