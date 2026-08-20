from pathlib import Path

from collector import PacketCapture
from models import CaptureConfig
from orchestrator import _normalize_legacy_args, load_scenarios


def test_legacy_cli_arguments_are_normalized() -> None:
    assert _normalize_legacy_args(["--config", "x.json", "--list"]) == [
        "list",
        "--config",
        "x.json",
    ]
    assert _normalize_legacy_args(["--config", "x.json", "--t9-code", "code"])[0] == "agent"


def test_capture_filter_is_targeted(tmp_path: Path) -> None:
    capture = PacketCapture(
        "capture",
        "container",
        "172.20.0.3",
        tmp_path / "capture.pcap",
        CaptureConfig(protocol="tcp", ports=[8080, 5005]),
    )
    expression = capture._build_filter()
    assert expression == "tcp and (port 8080 or port 5005)"


def test_example_catalog_loads() -> None:
    scenarios = load_scenarios(Path(__file__).parents[1] / "scenarios" / "example.json")
    assert len(scenarios) == 4
    by_code = {scenario.t9_code: scenario for scenario in scenarios}
    # Network struts2 scenario is agent-runnable.
    assert by_code["T9-25-01-S-N-CL"].agent_runnable_errors() == []
    # Endpoint-only scenario is not runnable (no Vulhub env / network capture).
    assert by_code["T9-25-03-S-E-HDF"].agent_runnable_errors()
    # The Log4Shell scenario is agent-runnable.
    assert by_code["T9-25-04-S-N-CD"].agent_runnable_errors() == []


def test_agent_subcommand_is_recognized() -> None:
    assert _normalize_legacy_args(["agent", "--config", "x.json"])[0] == "agent"
