"""Entry point for bundled local-only VILO backend."""
import os
import uvicorn
import server

if __name__ == '__main__':
    server.init_db()
    uvicorn.run(server.app,
                host='127.0.0.1',
                port=int(os.environ['VILO_PORT']),
                access_log=False,
                workers=1)
