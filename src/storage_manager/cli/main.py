"""Main CLI entry point for Storage Manager."""

import sys
import click
from rich.console import Console
from pathlib import Path

from ..utils import setup_logger, get_config_dir
from . import commands

console = Console()

@click.group()
@click.version_option(version='2.0.0')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--log-file', type=click.Path(), help='Save detailed log to file')
@click.pass_context
def cli(ctx, verbose, log_file):
    """
    🗄️  Storage Manager - Professional storage analysis and cleanup utility
    
    Intelligently scan, analyze, and clean your filesystem with advanced junk detection.
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['console'] = console
    
    # Setup logging
    log_path = Path(log_file) if log_file else None
    ctx.obj['logger'] = setup_logger('storage_manager', verbose=verbose, log_file=log_path)

# Register commands
cli.add_command(commands.scan)
cli.add_command(commands.clean)
cli.add_command(commands.analyze)
cli.add_command(commands.categories)

def main():
    """Main entry point."""
    try:
        cli(obj={})
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Operation cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"[red]✗ Error: {e}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main()
