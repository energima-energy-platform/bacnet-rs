"""A segmenting BACnet peer, for testing this crate's segmentation against a
stack that implements ASHRAE 135 clause 5.4 in full.

bacpypes3 rather than bacnet-stack: the C stack's CHANGELOG says outright that
it has "no support for segmentation in the TSM or APDU handlers", and its
`PDU_TYPE_SEGMENT_ACK` case only frees the invoke ID. bacpypes3 carries the
whole state machine - SEGMENTED_REQUEST, SEGMENTED_CONFIRMATION and
SEGMENTED_RESPONSE - so it can both send and receive segmented messages.

Serves a device whose Object_List is far too large for one APDU, so reading it
forces a segmented response, and accepts segmented requests so a large
ReadPropertyMultiple exercises the other direction.
"""

import argparse
import asyncio
import sys

from bacpypes3.local.analog import AnalogValueObject
from bacpypes3.app import Application
from bacpypes3.argparse import SimpleArgumentParser


async def main() -> None:
    parser = SimpleArgumentParser()
    parser.add_argument(
        "--objects",
        type=int,
        default=400,
        help="analog values to serve; 400 puts Object_List well past one APDU",
    )
    parser.add_argument(
        "--max-apdu",
        type=int,
        default=1476,
        help="the device's Max_APDU_Length_Accepted",
    )
    args = parser.parse_args()

    app = Application.from_args(args)

    # The three properties that make this peer useful. Without them bacpypes3
    # answers an oversized read with an Abort instead of segmenting it.
    device = app.device_object
    device.segmentationSupported = "segmentedBoth"
    device.maxSegmentsAccepted = 64
    device.maxApduLengthAccepted = args.max_apdu

    for instance in range(args.objects):
        app.add_object(
            AnalogValueObject(
                objectIdentifier=("analogValue", instance),
                objectName=f"AV-{instance}",
                presentValue=float(instance),
                units="degreesCelsius",
            )
        )

    # bacpypes3 binds its socket before it finishes wiring the protocol to
    # the stack behind it: a datagram arriving in that gap raises
    # `'IPv4DatagramProtocol' object has no attribute 'server'` inside
    # bacpypes3 and is dropped. The readiness event that closes the gap
    # (`IPv4DatagramServer._local_transport_ready`) is private, so this yields
    # to the event loop instead and lets the tasks created during construction
    # finish. Without it the first request of every test is answered only
    # after the client retransmits, which is a five-second stall per test and
    # would mask a real fault in retransmission.
    await asyncio.sleep(1.0)

    # Counted from the application rather than from the argument, because
    # bacpypes3 adds objects of its own - a NetworkPort for the address it was
    # given - and the Rust side asserts on what the device actually serves.
    served = sum(1 for _ in app.iter_objects())

    # The Rust side waits for this line before it sends anything, so the test
    # never races the socket being bound.
    print(f"ready objects={served}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
