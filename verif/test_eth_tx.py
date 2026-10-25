import cocotb

from cocotb.clock import Clock
from cocotb.triggers import RisingEdge


DATA_W = 16
KEEP_W = DATA_W // 8
BLOCK_BYTES = 8
UDP_HEADER_BYTES = 8
IPV4_MIN_HEADER_BYTES = 20
MAC_PREAMBLE_BYTES = 8
MAC_ADDR_BYTES = 6
MAC_TYPE_BYTES = 2
MAC_VLAN_BYTES = 4
FCS_BYTES = 4


def calculate_checksum(data):
    """Return a 16-bit one's-complement checksum for a byte sequence."""
    # Pad with a zero byte if the length is odd
    if len(data) % 2:
        data = list(data) + [0]

    total = 0
    for index in range(0, len(data), 2):
        # Make up 16-bit words
        word = (data[index] << 8) | data[index + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)

    # one's complement of the sum
    checksum = (~total) & 0xFFFF

    # If the checksum is zero, return 0xFFFF (as per RFC 768)
    checksum = 0xFFFF if checksum == 0 else checksum

    return checksum


def pack_le_bytes(data):
    """Pack up to KEEP_W bytes into one little-endian application beat."""
    beat = 0
    for index, byte in enumerate(data):
        beat |= byte << (8 * index)
    return beat


def last_block_info(byte_offset, packet_len):
    """Return whether this beat starts the final MAC block and its tail length."""
    starts_last_block = (byte_offset % BLOCK_BYTES == 0) and (
        byte_offset // BLOCK_BYTES == packet_len // BLOCK_BYTES
    )
    last_block_len = packet_len % BLOCK_BYTES if starts_last_block else 0
    return starts_last_block, last_block_len


def canonical_frame_bytes(frame_bytes):
    """Convert little-endian 16-bit bus words back to canonical wire byte order."""
    canonical = []
    for index in range(0, len(frame_bytes), 2):
        if index + 1 >= len(frame_bytes):
            break
        lo, hi = frame_bytes[index], frame_bytes[index + 1]
        canonical.extend([hi, lo])
    return bytes(canonical)


def wire_to_app_bytes(payload_wire):
    """Convert wire-order payload bytes back to application byte order."""
    app = []
    for index in range(0, len(payload_wire), 2):
        if index + 1 < len(payload_wire):
            app.extend([payload_wire[index + 1], payload_wire[index]])
        else:
            # Odd trailing byte keeps its position in this DUT stream.
            app.append(payload_wire[index])
    return bytes(app)


def parse_frame_headers(wire):
    """Parse MAC/IP/UDP headers from canonical wire bytes.

    The DUT can emit stack headers in a non-wire order, so this parser finds header
    locations using protocol markers rather than fixed absolute offsets.
    """
    min_frame = UDP_HEADER_BYTES + IPV4_MIN_HEADER_BYTES + MAC_PREAMBLE_BYTES + 2 * MAC_ADDR_BYTES + MAC_TYPE_BYTES + FCS_BYTES
    if len(wire) < min_frame:
        raise ValueError(f"frame too short: {len(wire)}")

    mac_type_offset = -1
    vlan = None
    for index in range(0, len(wire) - 2):
        if wire[index:index + 2] != b"\x08\x00":
            continue
        candidate_vlan = None
        if index >= 4 and wire[index - 4:index - 2] == b"\x81\x00":
            candidate_vlan = wire[index - 4:index]
            mac_start = index - (MAC_PREAMBLE_BYTES + 2 * MAC_ADDR_BYTES + MAC_VLAN_BYTES)
        else:
            mac_start = index - (MAC_PREAMBLE_BYTES + 2 * MAC_ADDR_BYTES)
        if mac_start >= 0:
            mac_type_offset = index
            vlan = candidate_vlan
            break

    if mac_type_offset < 0:
        raise ValueError("could not locate MAC ethertype 0x0800")

    ethertype = 0x0800
    mac_offset = (
        mac_type_offset - (MAC_PREAMBLE_BYTES + 2 * MAC_ADDR_BYTES + (MAC_VLAN_BYTES if vlan else 0))
    )
    preamble = wire[mac_offset:mac_offset + MAC_PREAMBLE_BYTES]
    cursor = mac_offset + MAC_PREAMBLE_BYTES
    mac_dst = wire[cursor:cursor + MAC_ADDR_BYTES]
    cursor += MAC_ADDR_BYTES
    mac_src = wire[cursor:cursor + MAC_ADDR_BYTES]
    cursor += MAC_ADDR_BYTES

    if vlan:
        cursor += MAC_VLAN_BYTES
    cursor += MAC_TYPE_BYTES

    def parse_ip_at(ip_offset):
        if ip_offset < 0 or len(wire) < ip_offset + IPV4_MIN_HEADER_BYTES:
            return None
        ip_version = (wire[ip_offset] >> 4) & 0xF
        ip_ihl = wire[ip_offset] & 0xF
        ip_header_len = ip_ihl * 4
        if ip_version != 4:
            return None
        if len(wire) < ip_offset + ip_header_len:
            return None
        ip_total_len = int.from_bytes(wire[ip_offset + 2:ip_offset + 4], byteorder="big")
        ip_proto = wire[ip_offset + 9]
        if ip_proto != 0x11:
            return None
        ip_src = wire[ip_offset + 12:ip_offset + 16]
        ip_dst = wire[ip_offset + 16:ip_offset + 20]
        return {
            "ip_offset": ip_offset,
            "ip_version": ip_version,
            "ip_ihl": ip_ihl,
            "ip_header_len": ip_header_len,
            "ip_total_len": ip_total_len,
            "ip_proto": ip_proto,
            "ip_src": ip_src,
            "ip_dst": ip_dst,
        }

    layout = None
    ip_info = parse_ip_at(mac_type_offset + MAC_TYPE_BYTES)
    if ip_info is not None:
        udp_offset = ip_info["ip_offset"] + ip_info["ip_header_len"]
        payload_offset = udp_offset + UDP_HEADER_BYTES
        layout = "MAC_IP_UDP"
    else:
        ip_info = parse_ip_at(mac_offset - IPV4_MIN_HEADER_BYTES - UDP_HEADER_BYTES)
        if ip_info is None:
            raise ValueError("could not locate IPv4 header adjacent to MAC/UDP")
        udp_offset = ip_info["ip_offset"] - UDP_HEADER_BYTES
        payload_offset = cursor
        layout = "UDP_IP_MAC"

    if udp_offset < 0 or len(wire) < udp_offset + UDP_HEADER_BYTES:
        raise ValueError("frame too short for UDP header")

    udp_src_port = int.from_bytes(wire[udp_offset:udp_offset + 2], byteorder="big")
    udp_dst_port = int.from_bytes(wire[udp_offset + 2:udp_offset + 4], byteorder="big")
    udp_len = int.from_bytes(wire[udp_offset + 4:udp_offset + 6], byteorder="big")
    udp_csum = int.from_bytes(wire[udp_offset + 6:udp_offset + 8], byteorder="big")
    if udp_len < UDP_HEADER_BYTES:
        raise ValueError(f"invalid UDP length {udp_len}")
    if ip_info["ip_total_len"] != ip_info["ip_header_len"] + udp_len:
        raise ValueError(
            f"IP length mismatch total={ip_info['ip_total_len']} ihl={ip_info['ip_header_len']} udp_len={udp_len}"
        )

    payload_len = udp_len - UDP_HEADER_BYTES
    payload_end = payload_offset + payload_len
    fcs_offset = payload_end
    expected_total_len = fcs_offset + FCS_BYTES
    if len(wire) != expected_total_len:
        raise ValueError(
            f"length mismatch: frame={len(wire)} expected={expected_total_len}"
        )

    return {
        "preamble": preamble,
        "mac_dst": mac_dst,
        "mac_src": mac_src,
        "vlan": vlan,
        "ethertype": ethertype,
        "layout": layout,
        "ip_offset": ip_info["ip_offset"],
        "ip_version": ip_info["ip_version"],
        "ip_ihl": ip_info["ip_ihl"],
        "ip_total_len": ip_info["ip_total_len"],
        "ip_ttl": wire[ip_info["ip_offset"] + 8],
        "ip_proto": ip_info["ip_proto"],
        "ip_src": ip_info["ip_src"],
        "ip_dst": ip_info["ip_dst"],
        "udp_offset": udp_offset,
        "udp_src_port": udp_src_port,
        "udp_dst_port": udp_dst_port,
        "udp_len": udp_len,
        "udp_csum": udp_csum,
        "payload_offset": payload_offset,
        "payload_end": payload_end,
        "fcs_offset": fcs_offset,
    }


def format_mac(addr_bytes):
    return ":".join(f"{byte:02x}" for byte in addr_bytes)


def format_ipv4(addr_bytes):
    return ".".join(str(byte) for byte in addr_bytes)


def pretty_print_frame(frame_bytes):
    """Pretty-print the emitted frame from the DUT.

    The DUT serialises data on a 16-bit bus in little-endian beat order. The raw bytes
    therefore need a word-wise canonicalisation before the frame headers can be decoded, and
    the payload itself needs to be reassembled in the original application byte order.

    Header offsets are detected from protocol markers, then decoded as MAC/IP/UDP.
    """
    if len(frame_bytes) < 4:
        return "packet too short"

    raw = bytes(frame_bytes)
    wire = canonical_frame_bytes(raw)
    wire_hex = " ".join(f"{byte:02x}" for byte in wire)

    parsed = parse_frame_headers(wire)

    mac_preamble = parsed["preamble"]
    mac_dst = parsed["mac_dst"]
    mac_src = parsed["mac_src"]
    vlan = parsed["vlan"]

    ip_src = format_ipv4(parsed["ip_src"])
    ip_dst = format_ipv4(parsed["ip_dst"])

    payload_region = wire[parsed["payload_offset"]:parsed["payload_end"]]
    payload = wire_to_app_bytes(payload_region)
    fcs_hex = " ".join(f"{byte:02x}" for byte in raw[-4:]) if len(raw) >= 4 else "(none)"

    lines = [
        "RAW BUS-ORDER BYTES:",
        " ".join(f"{byte:02x}" for byte in raw),
        "",
        "CANONICAL WIRE BYTES:",
        wire_hex,
        "",
        "FRAME LAYOUT:",
        f"  {parsed['layout']} -> payload -> FCS",
        "",
        "MAC HEADER:",
        f"  preamble = {' '.join(f'{b:02x}' for b in mac_preamble)}",
        f"  dst = {' '.join(f'{b:02x}' for b in mac_dst)}",
        f"  src = {' '.join(f'{b:02x}' for b in mac_src)}",
        f"  vlan = {' '.join(f'{b:02x}' for b in vlan)}" if vlan else "  vlan = (none)",
        f"  ethertype = 0x{parsed['ethertype']:04x}",
        "",
        "IP HEADER:",
        f"  version = {parsed['ip_version']}",
        f"  ihl = {parsed['ip_ihl']} words",
        f"  total_length = {parsed['ip_total_len']}",
        f"  ttl = {parsed['ip_ttl']}",
        f"  protocol = 0x{parsed['ip_proto']:02x}",
        f"  src = {ip_src}",
        f"  dst = {ip_dst}",
        "",
        "UDP HEADER:",
        f"  src_port = 0x{parsed['udp_src_port']:04x} ({parsed['udp_src_port']})",
        f"  dst_port = 0x{parsed['udp_dst_port']:04x} ({parsed['udp_dst_port']})",
        f"  udp_len = 0x{parsed['udp_len']:04x} ({parsed['udp_len']})",
        f"  checksum = 0x{parsed['udp_csum']:04x}",
        "",
        "PAYLOAD:",
        f"  {' '.join(f'{byte:02x}' for byte in payload)}" if payload else "  (empty)",
        "",
        "FCS:",
        f"  {fcs_hex}",
    ]
    return "\n".join(lines)


async def reset_dut(dut):
    """Reset the DUT"""
    dut._log.info("Resetting DUT")

    # Apply reset
    dut.nreset.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk)

    # deassert reset
    dut.nreset.value = 1
    for _ in range(5):
        await RisingEdge(dut.clk)

async def capture_phy_frame(dut):
    """Capture one full frame from PHY, including the terminating beat bytes."""

    dut.phy_ready_i.value = 1
    frame_bytes = []
    while True:
        await RisingEdge(dut.clk)
        idle = int(dut.phy_idle_o.value)
        ctrl = int(dut.phy_ctrl_v_o.value)
        start = int(dut.phy_start_o.value)
        term = int(dut.phy_term_o.value)
        term_len = int(dut.phy_term_len_o.value)

        if idle and not term and not frame_bytes:
            continue

        data_word = int(dut.phy_data_o.value)
        beat_bytes = list(data_word.to_bytes(KEEP_W, byteorder="little"))

        if term:
            assert 0 < term_len <= KEEP_W, f"invalid term_len={term_len}"
            frame_bytes.extend(beat_bytes[:term_len])
            return {
                "ctrl": ctrl,
                "start": start,
                "term_len": term_len,
                "last_beat_bytes": beat_bytes,
                "frame_bytes": bytes(frame_bytes),
            }

        frame_bytes.extend(beat_bytes)
        dut._log.info(
            "PHY BEAT ctrl=%d start=%d data=0x%0*x bytes=%s"
            % (
                ctrl,
                start,
                DATA_W // 4,
                data_word,
                " ".join(f"{byte:02x}" for byte in beat_bytes),
            )
        )


def check_captured_frame(dut, captured, expected_payload):
    """Parse and verify one captured frame using protocol headers."""

    frame_bytes = captured["frame_bytes"]
    term_len = captured["term_len"]
    wire = canonical_frame_bytes(frame_bytes)
    parsed = parse_frame_headers(wire)

    payload_wire = wire[parsed["payload_offset"]:parsed["payload_end"]]
    payload = wire_to_app_bytes(payload_wire)
    assert payload == bytes(expected_payload), (
        "payload mismatch from DUT: "
        f"got={[hex(x) for x in payload]} expected={[hex(x) for x in expected_payload]}"
    )

    expected_term_len = len(frame_bytes) % KEEP_W
    if expected_term_len == 0:
        expected_term_len = KEEP_W
    assert term_len == expected_term_len, (
        f"term_len mismatch: got {term_len}, expected {expected_term_len}"
    )

    dut._log.info(
        "PHY TERM ctrl=%d start=%d term_len=%d last_bytes=%s frame_len=%d\n%s"
        % (
            captured["ctrl"],
            captured["start"],
            term_len,
            " ".join(f"{byte:02x}" for byte in captured["last_beat_bytes"][:term_len]),
            len(frame_bytes),
            pretty_print_frame(frame_bytes),
        )
    )

async def default_inputs(dut):
    """Set default inputs for the DUT"""
    dut.app_cancel_i.value = 0
    dut.app_early_v_i.value = 0
    dut.app_last_i.value = 0
    dut.app_last_block_next_i.value = 0
    dut.app_last_block_next_len_i.value = 0
    dut.app_pkt_len_i.value = 0
    dut.app_cs_i.value = 0
    dut.app_data_i.value = 0
    dut.app_len_i.value = 0
    dut.phy_ready_i.value = 1

async def write_packet(dut, data):
    """Write a packet to the DUT.

    This test intentionally drives a packet whose length is not a multiple of the
    bus width so the last beat is partial; that checks the `app_len_i` and
    `app_last_i` control path as well as the `app_last_block_next_*` markers.
    """
    length = len(data)
    dut._log.info(
        "Writing packet length=%d (beat_width=%d, tail_bytes=%d): %s",
        length,
        KEEP_W,
        length % KEEP_W,
        data,
    )

    checksum = calculate_checksum(data)

    # Drive the total application packet length and checksum once per packet.
    dut.app_pkt_len_i.value = length
    dut.app_cs_i.value = checksum

    # Request early header generation, then wait until the DUT accepts the packet.
    dut.app_early_v_i.value = 1
    while dut.app_ready_v_o.value == 0:
        await RisingEdge(dut.clk)
    dut.app_early_v_i.value = 0

    # Drive the packet one beat at a time.
    for byte_offset in range(0, length, KEEP_W):
        beat_bytes = data[byte_offset:byte_offset + KEEP_W]
        beat_len = len(beat_bytes)
        is_last = (byte_offset + beat_len) == length
        is_last_block_next, last_block_len = last_block_info(byte_offset, length)

        dut.app_data_i.value = pack_le_bytes(beat_bytes)
        dut.app_len_i.value = beat_len
        dut.app_last_i.value = int(is_last)
        dut.app_last_block_next_i.value = int(is_last_block_next)
        dut.app_last_block_next_len_i.value = last_block_len if is_last_block_next else 0

        await RisingEdge(dut.clk)

    # Return to idle after the packet has been accepted, then give the PHY side time to
    # drain the last frame before the test exits. Without this delay the monitor may end
    # the simulation before a final end-of-frame flush is observed.
    dut.app_last_i.value = 0
    dut.app_last_block_next_i.value = 0
    dut.app_last_block_next_len_i.value = 0
    dut.app_len_i.value = 0
    for _ in range(20):
        await RisingEdge(dut.clk)

@cocotb.test()
async def test_eth_tx(dut):
    """Test eth_tx"""
    dut._log.info("Running test_eth_tx")

    # Start clock
    cocotb.start_soon(Clock(dut.clk, 10, unit="ns").start())

    # Reset DUT
    await reset_dut(dut)
    await default_inputs(dut)

    # Use a payload length that is not aligned to the beat width so the final beat is
    # partial. This exercises the control-path logic for `app_last_i`, `app_last_block_next_i`,
    # and `app_len_i` on the final cycle.
    payload = [((index * 0x11) + 0x07) & 0xFF for index in range(17)]

    # Capture one full frame from PHY while driving the packet.
    writer_task = cocotb.start_soon(write_packet(dut, payload))
    captured = await capture_phy_frame(dut)
    await writer_task

    check_captured_frame(dut, captured, payload)
