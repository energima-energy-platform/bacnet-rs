"""A segmenting BACnet peer, for testing this crate against a stack that
implements ASHRAE 135 clause 5.4 in full.

bacpypes3 rather than bacnet-stack, whose CHANGELOG says it has "no support for
segmentation in the TSM or APDU handlers".

Serves a device whose Object_List is far too large for one APDU, and accepts
segmented requests, so both directions can be exercised.
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
        help="analog values to serve; 400 puts Object_List past one APDU",
    )
    parser.add_argument(
        "--max-apdu",
        type=int,
        default=1476,
        help="the device's Max_APDU_Length_Accepted",
    )
    args = parser.parse_args()

    app = Application.from_args(args)

    # Without these bacpypes3 aborts an oversized read instead of segmenting.
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

    # bacpypes3 binds its socket before wiring the protocol behind it, and a
    # datagram arriving in that gap is dropped. Its readiness event is private,
    # so yield instead. Without this the first request of every test is answered
    # only after a retransmit - a five-second stall that would mask a real
    # retransmission fault.
    await asyncio.sleep(1.0)

    # From the application, not the argument: bacpypes3 adds a NetworkPort of
    # its own, and the Rust side asserts on what is actually served.
    served = sum(1 for _ in app.iter_objects())

    # The Rust side waits for this line before sending anything.
    print(f"ready objects={served}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
