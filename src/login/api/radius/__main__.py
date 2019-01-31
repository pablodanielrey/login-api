import asyncio
import logging
import traceback

from pyrad.dictionary import Dictionary
from pyrad.packet import AccessAccept
from pyrad.server import RemoteHost

from .server import RadiusServer

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except:
    pass

logging.basicConfig(level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")


if __name__ == '__main__':

    # create server and read dictionary
    loop = asyncio.get_event_loop()
    server = RadiusServer(loop=loop, dictionary=Dictionary('src/login/api/radius/dictionary'))

    # add clients (address, secret, name)
    server.hosts["192.168.0.105"] = RemoteHost("192.168.0.105",
                                           b"algodeclave",
                                           "192.168.0.105")

    try:

        # Initialize transports
        loop.run_until_complete(
            asyncio.ensure_future(
                server.initialize_transports(enable_auth=True,
                                             enable_acct=True,
                                             enable_coa=True,
                                             addresses=['0.0.0.0','127.0.0.1'])))

        try:
            # start server
            loop.run_forever()
        except KeyboardInterrupt as k:
            pass

        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    except Exception as exc:
        print('Error: ', exc)
        print('\n'.join(traceback.format_exc().splitlines()))
        # Close transports
        loop.run_until_complete(asyncio.ensure_future(
            server.deinitialize_transports()))

    loop.close()
