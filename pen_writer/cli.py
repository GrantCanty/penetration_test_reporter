from typing import Optional, List
import typer
from pen_writer import __app_name__, __version__
from pathlib import Path
import pen_writer.pen_tester_2

from pen_writer import (
    ERRORS, SUCCESS, __app_name__, __version__
)


app = typer.Typer()

@app.command()
def scan(
    target: str,
    port: Optional[int] = typer.Option(None, "--port", "-p")
) -> None:
    if port is not None:
        res, err = pen_writer.pen_tester_2.scanner(target, port)
    else:
        res, err = pen_writer.pen_tester_2.scanner(target)

    if err:
        typer.secho(f'Error: {ERRORS[err]}')
        raise typer.Exit(1)

def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"{__app_name__} v{__version__}")
        raise typer.Exit()

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the application's version and exit.",
        callback=_version_callback,
        is_eager=True,
    )
) -> None:
    return