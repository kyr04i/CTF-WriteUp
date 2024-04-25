#! /usr/bin/env bash
# Copyright Gerhard Rieger and contributors (see file CHANGES)
# Published under the GNU General Public License V.2, see file COPYING

# Shell script to perform group communications, sometimes called brokering.
# It starts a Socat instance that forks a child process for each
# connected client; the clients communicate via IPv4 broadcast

# Examples:

#   socat-broker.sh TCP-L:1234
# Now connect with an arbitrary number of clients like TCP:<server>:1234

#   socat-broker.sh SSL-L:1234,cert=server.pem,cafile=clients.crt
# Now connect with an arbitrary number of clients like SSL:<server>:1234,cafile=server.cert=clients.pem

ECHO="echo -e"

usage () {
    $ECHO "Usage: $0 <options> <listener>"
    $ECHO "	<listener> is a passive address like TCP4-L or SSL-L"
    $ECHO "	<options>:"
    $ECHO "		-d*  -S  -t <timeout>  -T <timeout> 	are passed to socat"
    $ECHO "		-V	prints the socat command before starting it"
    $ECHO "For example:"
    $ECHO "	$0 \\"
    $ECHO "		TCP4-L:1234"
    $ECHO "Then connect with clients to port 1234"
    $ECHO "Data sent by any client is forwarded to all other clients"
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
	X-*) echo "Unknown option \"$1\"" >&2
	     usage >&2
	     exit 1 ;;
	*) break ;;
    esac
    shift
done

LISTENER="$1"

if [ -z "$LISTENER" ]; then
    echo "$0: Missing parameter" >&2
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

PORT=$($SOCAT -d -d -T 0.000001 UDP4-RECV:0 /dev/null 2>&1 |grep bound |sed 's/.*:\([1-9][0-9]*\)$/\1/')
if [ -z "$PORT" ]; then
    echo "$0: Failed to determine free UDP port" >&2
    exit 1
fi

BCADDR=127.255.255.255

if [ "$VERBOSE" ]; then
    echo -e "$SOCAT -lp socat-broker $OPTS \\
	$LISTENER \
	UDP4-DATAGRAM:$BCADDR:$PORT,bind=:$PORT,so-broadcast,so-reuseaddr"
fi	
$SOCAT -lp socat-broker $OPTS \
    "$LISTENER" \
    "UDP4-DATAGRAM:$BCADDR:$PORT,bind=:$PORT,so-broadcast,so-reuseaddr"

