from typing import Optional, List
import typer
from pen_writer import __app_name__, __version__
from pathlib import Path
import pen_writer.pen_tester_2
from datetime import datetime
import pen_writer.summarizer

from pen_writer import (
    ERRORS, SUCCESS, __app_name__, __version__
)


app = typer.Typer()

@app.command()
def scan(
    target: str,
    port: Optional[int] = typer.Option(None, "--port", "-p"),
    base_path: Optional[str] = typer.Option(None, "--base_path", '-b')
) -> None:
    parent_path = Path(Path(__file__).resolve().parent.parent, 'outputs')
    output_dir = datetime.today().strftime('%Y_%m_%d_%H_%M_%S')
    print(f'Running scans on target:{target} basepath:{base_path} port:{port}')
    print(f'Results from scans will be saved in {parent_path / output_dir}')
    
    if port is not None:
        res, err = pen_writer.pen_tester_2.scanner(target, parent_path, port, output_dir, base_path)
    else:
        res, err = pen_writer.pen_tester_2.scanner(target, parent_path, output_dir=output_dir, base_path=base_path)

    if err:
        typer.secho(f'Error: {ERRORS[err]}')
        raise typer.Exit(1)
    
    print(f'Completed scans on target:{target} basepath:{base_path} port:{port}')

    print('Generating report')
    pen_writer.summarizer.summarize(parent_path, output_dir)

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