import asyncio
import logging
import socket
import ssl
from datetime import datetime
from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration

SERVER_IP = "18.118.51.173"
SERVER_PORT = 4433
CLIENT_BIND_IP = "43.203.189.22"
ALPNS = ["hq-29"]

logging.basicConfig(level=logging.INFO)

def ts():
    return datetime.now().isoformat(timespec="milliseconds")


async def main():
    cfg = QuicConfiguration(is_client=True, alpn_protocols=ALPNS)
    cfg.verify_mode = ssl.CERT_NONE

    # 항상 Initial부터 시작 (세션 재개 방지)
    def _drop_ticket(ticket): pass
    cfg.session_ticket_handler = _drop_ticket

    # 바인딩
    local_addr = None
    try:
        socket.getaddrinfo(CLIENT_BIND_IP, 0)
        local_addr = (CLIENT_BIND_IP, 0)
    except Exception:
        logging.warning("[client] cannot bind to %s, fallback to OS default", CLIENT_BIND_IP)

    t0 = ts()
    logging.info("[T0 initial-send-queued] %s (starting QUIC handshake)", t0)

    retry_time = None

    # 내부 로깅 hook을 통한 retry 감지
    import logging as pylog
    class RetryFilter(pylog.Filter):
        def filter(self, record):
            nonlocal retry_time
            if "Retrying with token" in record.getMessage():
                retry_time = ts()
                logging.info("[T_retry retry-token-received] %s", retry_time)
            return True
    pylog.getLogger("quic").addFilter(RetryFilter())

    async with connect(
        SERVER_IP,
        SERVER_PORT,
        configuration=cfg,
        wait_connected=True,
        # local_addr=local_addr,
        # server_name="example.com",
    ) as client:
        t1 = ts()
        logging.info("[T1 handshake-completed] %s", t1)

        reader, writer = await client.create_stream()
        msg = b"hello from aioquic client!"
        writer.write(msg)
        await writer.drain()
        writer.write_eof()

        t2 = ts()
        logging.info("[T2 appdata-sent] %s (%d bytes)", t2, len(msg))

        # 에코 수신
        need = len(msg)
        chunks = []
        while need > 0:
            chunk = await reader.read(need)
            if not chunk:
                break
            chunks.append(chunk)
            need -= len(chunk)
        echo = b"".join(chunks)

        t3 = ts()
        logging.info("[T3 appdata-received] %s (%d bytes) -> %r", t3, len(echo), echo)

        # 요약
        logging.info(
            "SUMMARY: handshake=%.1f ms | retry_time=%s | send=%s | recv=%s",
            (datetime.fromisoformat(t1) - datetime.fromisoformat(t0)).total_seconds() * 1000,
            retry_time,
            t2,
            t3,
        )


if __name__ == "__main__":
    asyncio.run(main())