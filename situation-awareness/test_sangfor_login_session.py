from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sangfor_login_session import build_parser


def test_parser_defaults_to_project_secrets_session_file():
    args = build_parser().parse_args([])
    expected = Path(__file__).resolve().parents[1] / "secrets" / "sip_session.json"
    assert Path(args.session_file) == expected


def test_parser_accepts_encrypted_credentials_and_chaojiying_options():
    args = build_parser().parse_args([
        "--credentials-file",
        "secrets/login.json.gpg",
        "--captcha-provider",
        "chaojiying",
        "--chaojiying-codetype",
        "1902",
    ])
    assert args.credentials_file == "secrets/login.json.gpg"
    assert args.captcha_provider == "chaojiying"
    assert args.chaojiying_codetype == "1902"
