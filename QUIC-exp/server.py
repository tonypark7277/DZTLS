import asyncio
import logging
import argparse
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration

DEFAULT_HOST = "0.0.0.0"  # 모든 NIC에 바인드
DEFAULT_PORT = 4433
ALPNS = ["hq-29"]  # 클라이언트와 동일하게

logging.basicConfig(level=logging.INFO)


async def handle_stream(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:  # EOF
                break
            logging.info(f"[server] recv {len(data)} bytes: {data!r}")
            writer.write(data)
            await writer.drain()        
        writer.write_eof()
        await writer.drain()
    except Exception:
        logging.exception("[server] stream handler error")


async def main():
    parser = argparse.ArgumentParser(description="aioquic echo server with SAV toggle")
    parser.add_argument("--host", default=DEFAULT_HOST, help="bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="UDP port (default: 4433)")
    sav_group = parser.add_mutually_exclusive_group()
    sav_group.add_argument("--sav", dest="sav", action="store_true", help="enable SAV (Retry)")
    sav_group.add_argument("--no-sav", dest="sav", action="store_false", help="disable SAV")
    parser.set_defaults(sav=True)  # 기본값: SAV 켬
    parser.add_argument("--cert", default="certs/cert.pem", help="path to cert PEM")
    parser.add_argument("--key", default="certs/key.pem", help="path to key PEM")
    args = parser.parse_args()

    cfg = QuicConfiguration(is_client=False, alpn_protocols=ALPNS)
    cfg.load_cert_chain(args.cert, args.key)

    await serve(
        host=args.host,
        port=args.port,
        configuration=cfg,
        stream_handler=handle_stream,
        retry=args.sav,  # ← 여기에서 SAV 토글 (True면 SAV 켬)
    )

    logging.info(
        "[server] listening on %s:%d | SAV(retry)=%s",
        args.host, args.port, "ON" if args.sav else "OFF"
    )

    # 서버 지속 실행
    await asyncio.get_running_loop().create_future()


if __name__ == "__main__":
    asyncio.run(main())

