from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sangfor_login_session import build_parser


def test_parser_defaults_to_project_secrets_session_file():
    args = build_parser().parse_args([])
    expected = Path(__file__).resolve().parents[1] / "secrets" / "sip_session.json"
    assert Path(args.session_file) == expected
