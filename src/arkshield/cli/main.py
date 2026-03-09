"""
Arkshield — CLI (Command Line Interface)

The primary console-based interface for interacting with the platform.
Supports monitoring, response triggering, and configuration management.
"""

import sys
import click
import requests
import json
import time
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.progress import Progress

console = Console()

API_BASE = "http://localhost:8000"

@click.group()
def cli():
    """Arkshield: Next-Gen Autonomous Cyber Defense CLI"""
    pass

@cli.command()
def status():
    """Check the status of the sentinel agent and API."""
    try:
        response = requests.get(f"{API_BASE}/status", timeout=10)
        if response.status_code == 200:
            data = response.json()
            status_text = "[bold green]ONLINE[/bold green]" if data['status'] == 'active' else "[bold yellow]INITIALIZING[/bold yellow]"
            console.print(Panel(
                f"Status: {status_text}\n"
                f"ID: {data['id']}\n"
                f"Version: {data['version']}\n"
                f"Monitors: {', '.join(data['monitors']) if data['monitors'] else 'None'}\n"
                f"Uptime: {data['uptime_seconds']}s",
                title="Arkshield Status",
                border_style="blue"
            ))
        else:
            console.print(f"[bold red]Sentinel API error: {response.status_code}[/bold red]")
    except requests.exceptions.Timeout:
        console.print("[bold red]Sentinel API request timed out. The system might be under heavy load.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Sentinel API is OFFLINE or unreachable.[/bold red]")

@cli.command()
@click.option('--limit', default=10, help='Number of alerts to show')
def alerts(limit):
    """View recent security alerts."""
    try:
        response = requests.get(f"{API_BASE}/alerts", timeout=3)
        alerts = response.json()[:limit]
        
        table = Table(title="Recent Security Incidents")
        table.add_column("Time", style="cyan")
        table.add_column("Pattern", style="bold white")
        table.add_column("Category", style="magenta")
        table.add_column("Severity", style="red")
        table.add_column("Risk", style="yellow")

        for alert in alerts:
            sev_color = "red" if alert['severity'] >= 4 else ("yellow" if alert['severity'] >= 3 else "blue")
            table.add_row(
                alert['created_at'].split('T')[1][:8],
                alert['title'],
                alert['category'],
                f"[{sev_color}]{alert['severity']}[/{sev_color}]",
                f"{alert['risk_score']:.1f}"
            )
            
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Failed to fetch alerts: {e}[/bold red]")

@cli.command()
@click.argument('pid', type=int)
def kill(pid):
    """Manually terminate a process."""
    if click.confirm(f"Are you sure you want to kill process {pid}?"):
        try:
            response = requests.post(f"{API_BASE}/actions/kill/{pid}")
            if response.status_code == 200:
                console.print(f"[bold green]Successfully killed PID {pid}[/bold green]")
            else:
                console.print(f"[bold red]Kill action failed: {response.json().get('detail')}[/bold red]")
        except Exception as e:
            console.print(f"[bold red]Error: {e}[/bold red]")

@cli.command()
def start():
    """Launch the Arkshield platform (Agent + API)."""
    from arkshield.api.server import start_api
    console.print("[bold green]Starting Arkshield Platform...[/bold green]")
    try:
        start_api()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Platform stopped by user.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Failed to start platform: {e}[/bold red]")

@cli.command()
def scan():
    """Trigger an immediate scanning cycle."""
    try:
        with console.status("[bold green]Triggering system-wide scan..."):
            response = requests.post(f"{API_BASE}/scan", timeout=45) # High timeout for deep scans
        if response.status_code == 200:
            console.print(f"[bold green]Scan complete. Captured {response.json()['events_captured']} new events.[/bold green]")
        else:
            console.print(f"[bold red]Scan failed with status: {response.status_code}[/bold red]")
    except requests.exceptions.Timeout:
        console.print("[bold yellow]Scan request timed out on the client side, but the scan may still be running in the background.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")

@cli.command()
def logs():
    """Stream the platform logs."""
    log_file = "arkshield.log"
    if not os.path.exists(log_file):
        console.print(f"[bold red]Log file {log_file} not found.[/bold red]")
        return
    
    console.print(f"--- Streaming {log_file} ---", style="bold blue")
    try:
        with open(log_file, 'r') as f:
            # Go to end of file
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                console.print(line.strip())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Log stream stopped.[/bold yellow]")

@cli.command()
def monitor():
    """Real-time monitoring dashboard in CLI."""
    with Live(console=console, refresh_per_second=1) as live:
        while True:
            stats = None
            alerts_data = None
            api_online = True
            try:
                # Optimized fetching with individual timeouts
                try:
                    stats_resp = requests.get(f"{API_BASE}/stats", timeout=5)
                    if stats_resp.status_code == 200:
                        stats = stats_resp.json()
                    
                    alerts_resp = requests.get(f"{API_BASE}/alerts", timeout=5)
                    if alerts_resp.status_code == 200:
                        alerts_data = alerts_resp.json()[:5]
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                    # API is busy or just went down, show busy state instead of crashing
                    if stats is None: api_online = False
                
                if api_online and stats:
                    # Build Dashboard
                    table = Table.grid(expand=True)
                    table.add_column(justify="left", ratio=1)
                    table.add_column(justify="right", ratio=1)
                    
                    stats_content = (
                        f"[cyan]Events Processed:[/cyan] [bold]{stats['events_processed']}[/bold]\n"
                        f"[yellow]Alerts Generated:[/yellow] [bold]{stats['alerts_generated']}[/bold]\n"
                        f"[red]Threats Blocked:[/red]  [bold]{stats['threats_detected']}[/bold]\n"
                        f"[green]Security Posture:[/green] [bold]{stats['security_score']}%[/bold]"
                    )
                    
                    alerts_content = "\n".join([
                        f"• {a['title']} ([red]S:{a['severity']}[/red])" for a in alerts_data
                    ]) if alerts_data else "[dim]Watching for threats...[/dim]"
                    
                    table.add_row(
                        Panel(stats_content, title="[bold blue]Live Statistics[/bold blue]", border_style="blue"),
                        Panel(alerts_content, title="[bold red]Recent Alerts[/bold red]", border_style="red")
                    )
                    
                    live.update(table)
                else:
                    live.update(Panel("[bold yellow]SYSTEM BUSY OR INITIALIZING...[/bold yellow]\n[dim]The API is currently processing heavy tasks.[/dim]", border_style="yellow"))
                
                time.sleep(1)
            except Exception as e:
                live.update(Panel(f"[bold red]ARKSHIELD API DISCONNECTED[/bold red]\n[dim]{str(e)}[/dim]", border_style="red"))
                time.sleep(2)

if __name__ == "__main__":
    cli()
