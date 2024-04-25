#! /usr/bin/env bash
# Copyright Gerhard Rieger and contributors (see file CHANGES)
# Published under the GNU General Public License V.2, see file COPYING

# Shell script to build a many-to-one, one-to-all communication
# It starts two Socat instances that communicate via IPv4 broadcast,
# the first of which forks a child process for each connected client.

# Example:

# Consider a serial device connected to the Internet on TCP port 1234, it
# accepts only one connection at a time.
# On a proxy/relay server run this script:
#   socat-mux.sh \
#       TCP-L:1234,reuseaddr,fork \
#       TCP:<addr-of-device>:1234
# Now connect with an arbitrary number of clients to TCP:<proxy>:1234;
# data sent by the device goes to all clients, data from any client is sent to
# the device.

ECHO="echo -e"

usage () {
    $ECHO "Usage: $0 <options> <listener> <target>"
    $ECHO "Example:"
    $ECHO "    $0 TCP4-L:1234,reuseaddr,fork TCP:10.2.3.4:12345"
    $ECHO "Clients may connect to port 1234; data sent by any client is forwarded to 10.2.3.4,"
    $ECHO "data provided by 10.2.3.4 is sent to ALL clients"
    $ECHO "    <options>:"
    $ECHO "\t-h\tShow this help text and exit"
    $ECHO "\t-V\tShow Socat commands"
    $ECHO "\t-q\tSuppress most messages"
    $ECHO "\t-d*\tOptions beginning with -d are passed to Socat processes"
    $ECHO "\t-l*\tOptions beginning with -l are passed to Socat processes"
    $ECHO "\t-b|-S|-t|-T|-l <arg>\tThese options are passed to Socat processes"
}

VERBOSE= QUIET= OPTS=
while [ "$1" ]; do
    case "X$1" in
	X-h) usage; exit ;;
	X-V) VERBOSE=1 ;;
	X-q) QUIET=1; OPTS="-d0" ;;
	X-d*|X-l?*) OPTS="$OPTS $1" ;;
	X-b|X-S|X-t|X-T|X-l) OPT=$1; shift; OPTS="$OPTS $OPT $1" ;;
	X-) break ;;
	X-*) echo "$0: Unknown option \"$1\"" >&2
	     usage >&2
	     exit 1 ;;
	*) break ;;
    esac
    shift
done

LISTENER="$1"
TARGET="$2"

if [ -z "$LISTENER" -o -z "$TARGET" ]; then
    echo "$0: Missing parameter(s)" >&2
    usage >&2
    exit 1
fi

shopt -s nocasematch
if ! [[ "$LISTENER" =~ .*,fork ]] || [[ "$LISTENER" =~ .*,fork, ]]; then
    LISTENER="$LISTENER,fork"
fi

case "$0" in
    */*) SOCAT=${0%/*}/socat ;;
    *) SOCAT=socat ;;
esac

PORT1=$($SOCAT -d -d -T 0.000001 UDP4-RECV:0 /dev/null 2>&1 |grep bound |sed 's/.*:\([1-9][0-9]*\)$/\1/')
PORT2=$($SOCAT -d -d -T 0.000001 UDP4-RECV:0 /dev/null 2>&1 |grep bound |sed 's/.*:\([1-9][0-9]*\)$/\1/')
if [ -z "$PORT1" -o -z "$PORT2" ]; then
    echo "$0: Failed to determine free UDP ports" >&2
    exit 1
fi
if [ "$PORT1" = "$PORT2" ]; then 	# seen on etch
    PORT2=$((PORT1+1))
fi

IFADDR=127.0.0.1
BCADDR=127.255.255.255


pid1= pid2=
trap '[ "$pid1" ] && kill $pid1 2>/dev/null; [ "$pid2" ] && kill $pid2 2>/dev/null' EXIT

set -bm
trap 'if kill -n 0 $pid1 2>/dev/null; then [ -z "$QUIET" ] && echo "$0: socat-listener exited with rc=$?" >&2; kill $pid1; else [ -z "$QUIET" ] && echo "$0: socat-multiplexer exited with rc=$?" >&2; kill $pid2 2>/dev/null; fi; exit 1' SIGCHLD

if [ "$VERBOSE" ]; then
    $ECHO "$SOCAT -lp muxfwd $OPTS \\
	\"$TARGET\" \\
	\"UDP4-DATAGRAM:$BCADDR:$PORT2,bind=$IFADDR:$PORT1,so-broadcast\" &"
fi
$SOCAT -lp muxfwd $OPTS \
    "$TARGET" \
    "UDP4-DATAGRAM:$BCADDR:$PORT2,bind=$IFADDR:$PORT1,so-broadcast" &
pid1=$!

if [ "$VERBOSE" ]; then
    $ECHO "$SOCAT -lp muxlst $OPTS \\
    	\"$LISTENER\" \\
        \"UDP4-DATAGRAM:$IFADDR:$PORT1,bind=:$PORT2,so-broadcast,so-reuseaddr\" &"
fi
$SOCAT -lp muxlst $OPTS \
    "$LISTENER" \
    "UDP4-DATAGRAM:$IFADDR:$PORT1,bind=:$PORT2,so-broadcast,so-reuseaddr" &
pid2=$!

wait
#wait -f
