# db.py
import asyncpg
import uuid
from datetime import datetime

class DB:
    def __init__(self, dsn):
        self.dsn = dsn
        self.pool = None

    async def get_account_ip_id(self, ip_address: str) -> int:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT id FROM account_ip WHERE ip = $1", ip_address)
            if row:
                return row["id"]
            raise ValueError(f"IP address {ip_address} not found in account_ip table")

    async def connect(self):
        self.pool = await asyncpg.create_pool(dsn=self.dsn)

    async def insert_log(self, source, msisdn, message, account_ip=0, gtw_id=0, telco_id=0, parts=1):
        msg_id = str(uuid.uuid4())
        ts = datetime.utcnow()

        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO log (
                    msg_id, source, msisdn, status, message, orig_msg,
                    ts, account_ip, gtw_id, telco_id, parts
                ) VALUES (
                    $1, $2, $3, 'waiting', $4, $4,
                    $5, $6, $7, $8, $9
                )
            """, msg_id, source, msisdn, message, ts, account_ip, gtw_id, telco_id, parts)

        return msg_id