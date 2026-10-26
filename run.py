"""运行入口：python run.py [--host 127.0.0.1] [--port 8080]"""

import argparse

from wscheck import create_app

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WSCHECK Web 安全检测工具")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    create_app().run(host=args.host, port=args.port, debug=args.debug, threaded=True)
