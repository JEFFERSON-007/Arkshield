"""CLI commands for Storage Manager."""

import click
from rich.console import Console
from rich.table import Table
from rich.progress import track
from pathlib import Path
from typing import List, Optional

from ..detectors import JunkDetector
from ..utils import human_size, is_protected_path, format_age

console = Console()

@click.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--categories', '-c', help='Junk categories to detect (comma-separated)', default=None)
@click.option('--dry-run', is_flag=True, help='Preview what would be detected without cleaning')
@click.option('--exclude', multiple=True, help='Exclude paths containing pattern')
@click.option('--include-hidden', is_flag=True, help='Include hidden files')
@click.option('--auto-confirm', is_flag=True, help='Skip confirmation prompts')
@click.pass_context
def clean(ctx, path, categories, dry_run, exclude, include_hidden, auto_confirm):
    """
    🧹 Clean junk files from specified path.
    
    Uses intelligent pattern matching to identify and remove temporary files,
    caches, logs, build artifacts, and other junk.
    
    Examples:
    \b
      storage-manager clean /path/to/dir
      storage-manager clean . --categories cache,logs,temporary
      storage-manager clean . --dry-run
    """
    from ..core.cleaner import StorageCleaner
    
    logger = ctx.obj['logger']
    target_path = Path(path).resolve()
    
    # Parse categories
    cat_list = [c.strip() for c in categories.split(',')] if categories else None
    
    # Show header
    console.print("\n[cyan]═══════════════════════════════════════════════════[/cyan]")
    console.print("[cyan bold]        🧹 STORAGE CLEANUP UTILITY[/cyan bold]")
    console.print("[cyan]═══════════════════════════════════════════════════[/cyan]\n")
    
    if dry_run:
        console.print("[yellow]📋 DRY-RUN MODE: No files will be deleted[/yellow]")
    else:
        console.print("[red]⚠️  CLEANUP MODE: Files will be moved to trash[/red]")
    
    console.print(f"[cyan]Target:[/cyan] {target_path}")
    if cat_list:
        console.print(f"[cyan]Categories:[/cyan] {', '.join(cat_list)}")
    console.print()
    
    # Initialize cleaner
    cleaner = StorageCleaner(
        logger=logger,
        dry_run=dry_run,
        categories=cat_list,
        exclude_patterns=set(exclude),
        include_hidden=include_hidden
    )
    
    # Scan for junk
    console.print("[cyan]🔍 Scanning for junk files...[/cyan]")
    junk_files = cleaner.find_junk_files(target_path)
    
    if not junk_files:
        console.print("[green]✓ No junk files found![/green]\n")
        return
    
    # Display summary
    total_size = sum(f['size'] for f in junk_files)
    console.print(f"\n[yellow]Found {len(junk_files)} junk files ({human_size(total_size)})[/yellow]\n")
    
    # Show samples
    console.print("[cyan]Sample files (first 10):[/cyan]")
    for i, file in enumerate(junk_files[:10], 1):
        cat_str = ', '.join(file['categories'])
        console.print(f"  {i}. {file['path']}")
        console.print(f"     [dim]Size: {human_size(file['size'])} | Categories: {cat_str}[/dim]")
    
    if len(junk_files) > 10:
        console.print(f"  [dim]... and {len(junk_files) - 10} more files[/dim]")
    
    # Confirm
    if not auto_confirm and not dry_run:
        if not click.confirm(f"\n⚠️  Proceed with cleanup of {len(junk_files)} files?", default=False):
            console.print("[yellow]Cleanup cancelled.[/yellow]\n")
            return
    
    # Clean
    console.print(f"\n[cyan]{'Previewing' if dry_run else 'Cleaning'} files...[/cyan]\n")
    summary = cleaner.cleanup_files(junk_files)
    
    # Show results
    console.print("\n[cyan]═══════════════════════════════════════════════════[/cyan]")
    console.print("[cyan bold]            CLEANUP SUMMARY[/cyan bold]")
    console.print("[cyan]═══════════════════════════════════════════════════[/cyan]\n")
    
    mode = "DRY-RUN (no files deleted)" if dry_run else "LIVE CLEANUP"
    console.print(f"[yellow]Mode:[/yellow] {mode}")
    console.print(f"[green]✓ Processed:[/green] {summary['total_processed']} files")
    console.print(f"[red]✗ Failed:[/red] {summary['total_failed']} files")
    console.print(f"[yellow]💾 Space {'that would be' if dry_run else ''} freed:[/yellow] {human_size(summary['space_freed'])}\n")

@click.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--limit', type=int, help='Limit number of files to scan')
@click.option('--include-hidden', is_flag=True, help='Include hidden files')
@click.option('--exclude', multiple=True, help='Exclude paths containing pattern')
@click.pass_context
def scan(ctx, path, limit, include_hidden, exclude):
    """
    📊 Scan and analyze filesystem storage.
    
    Provides detailed statistics about file types, sizes, and junk content.
    
    Examples:
    \b
      storage-manager scan /path/to/dir
      storage-manager scan . --limit 10000
      storage-manager scan . --exclude node_modules --exclude .git
    """
    from ..core.scanner import StorageScanner
    
    logger = ctx.obj['logger']
    target_path = Path(path).resolve()
    
    console.print("\n[cyan]═══════════════════════════════════════════════════[/cyan]")
    console.print("[cyan bold]        📊 STORAGE SCANNER[/cyan bold]")
    console.print("[cyan]═══════════════════════════════════════════════════[/cyan]\n")
    
    console.print(f"[cyan]Scanning:[/cyan] {target_path}\n")
    
    # Initialize scanner
    scanner = StorageScanner(
        logger=logger,
        include_hidden=include_hidden,
        exclude_patterns=set(exclude),
        limit=limit
    )
    
    # Scan
    results = scanner.scan(target_path)
    
    # Display results
    console.print("\n[cyan]═══════════════════════════════════════════════════[/cyan]")
    console.print("[cyan bold]            SCAN RESULTS[/cyan bold]")
    console.print("[cyan]═══════════════════════════════════════════════════[/cyan]\n")
    
    console.print(f"[green]Total files:[/green] {results['total_files']:,}")
    console.print(f"[green]Total size:[/green] {human_size(results['total_size'])}\n")
    
    # Junk summary
    if results['junk_stats']:
        console.print("[yellow]📦 Junk Files Detected:[/yellow]")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Category", style="yellow")
        table.add_column("Count", justify="right")
        table.add_column("Size", justify="right")
        
        for cat, stats in sorted(results['junk_stats'].items(), key=lambda x: x[1]['size'], reverse=True):
            table.add_row(
                cat,
                f"{stats['count']:,}",
                human_size(stats['size'])
            )
        
        console.print(table)
        console.print()

@click.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.pass_context
def analyze(ctx, path):
    """
    🔬 Deep analysis with recommendations.
    
    Provides detailed insights and actionable recommendations for cleanup.
    
    Example:
    \b
      storage-manager analyze /path/to/dir
    """
    console.print("\n[cyan]═══════════════════════════════════════════════════[/cyan]")
    console.print("[cyan bold]        🔬 DEEP ANALYSIS[/cyan bold]")
    console.print("[cyan]═══════════════════════════════════════════════════[/cyan]\n")
    
    console.print("[yellow]⚙️  Analysis feature coming soon![/yellow]\n")

@click.command()
@click.option('--detailed', '-d', is_flag=True, help='Show detailed patterns for each category')
@click.pass_context
def categories(ctx, detailed):
    """
    📋 List all available junk categories.
    
    Shows all junk detection categories with descriptions and examples.
    """
    from rich.panel import Panel
    from rich.columns import Columns
    
    detector = JunkDetector()
    
    if detailed:
        # Detailed view with full patterns
        console.print("\n[bold cyan]═══ JUNK DETECTION CATEGORIES (DETAILED) ═══[/bold cyan]\n")
        
        for i, cat_info in enumerate(detector.list_categories(), 1):
            cat_name = cat_info['name']
            pattern = detector.patterns[cat_name]
            
            # Build content
            content = f"[dim]{cat_info['description']}[/dim]\n"
            
            if 'extensions' in pattern and pattern['extensions']:
                content += f"\n[green]Extensions:[/green] {', '.join(pattern['extensions'][:5])}"
            
            if 'directories' in pattern and pattern['directories']:
                dirs = pattern['directories'][:3]
                content += f"\n[blue]Directories:[/blue] {', '.join(dirs)}"
            
            if 'filenames' in pattern and pattern['filenames']:
                content += f"\n[yellow]Patterns:[/yellow] {', '.join(pattern['filenames'][:3])}"
            
            if 'age_threshold_days' in pattern:
                content += f"\n[magenta]Age:[/magenta] >{pattern['age_threshold_days']} days old"
            
            if 'min_size_mb' in pattern:
                content += f"\n[magenta]Size:[/magenta] >{pattern['min_size_mb']}MB"
            
            panel = Panel(content, title=f"[bold yellow]{i}. {cat_name}[/bold yellow]", 
                         border_style="cyan", padding=(0, 1))
            console.print(panel)
    
    else:
        # Compact organized view
        console.print("\n")
        console.print(Panel.fit(
            "[bold white]💾 JUNK DETECTION CATEGORIES[/bold white]\n"
            "[dim]Smart pattern-based detection across 10 categories[/dim]",
            border_style="bold cyan"
        ))
        console.print()
        
        # High Priority
        console.print("[bold red]🔥 HIGH IMPACT[/bold red] [dim](typically largest)[/dim]")
        categories_info = [
            ("build_artifacts", "⚙️", "Build artifacts", "node_modules, dist/, .gradle"),
            ("cache", "📦", "App caches", "__pycache__, .cache, .npm"),
            ("logs", "📄", "Large logs", "*.log files >1MB, >90 days"),
            ("temporary", "🗑️", "Temp files", ".tmp, .bak, ~* files"),
        ]
        
        for cat, icon, name, examples in categories_info:
            console.print(f"  {icon} [yellow]{cat:23}[/yellow] [white]{name:18}[/white] [dim]{examples}[/dim]")
        
        console.print()
        console.print("[bold blue]💻 DEVELOPMENT[/bold blue]")
        console.print(f"  🔧 [yellow]{'development_artifacts':23}[/yellow] [white]{'Dev tools':18}[/white] [dim].git/objects, coverage/[/dim]")
        
        console.print()
        console.print("[bold green]🌐 BROWSER & SYSTEM[/bold green]")
        sys_categories = [
            ("browser_data", "🌍", "Browser cache", "Cookies, Sessions, GPUCache"),
            ("windows_junk", "🪟", "Windows junk", "Thumbs.db, desktop.ini"),
            ("macos_junk", "🍎", "macOS junk", ".DS_Store, .Trashes"),
        ]
        
        for cat, icon, name, examples in sys_categories:
            if cat in detector.patterns:
                console.print(f"  {icon} [yellow]{cat:23}[/yellow] [white]{name:18}[/white] [dim]{examples}[/dim]")
        
        console.print()
        console.print("[bold magenta]📝 APP TEMP FILES[/bold magenta]")
        app_categories = [
            ("office_temp", "📊", "Office temp", "~$*.docx, .~lock.*"),
            ("editor_temp", "✏️", "Editor temp", ".swp, .swo, *~ files"),
        ]
        
        for cat, icon, name, examples in app_categories:
            console.print(f"  {icon} [yellow]{cat:23}[/yellow] [white]{name:18}[/white] [dim]{examples}[/dim]")
        
        console.print()
        console.print(Panel.fit(
            "[bold white]💡 Quick Start[/bold white]\n"
            "[cyan]storage-manager clean . --categories cache,logs --dry-run[/cyan]  [dim](preview)[/dim]\n"
            "[cyan]storage-manager categories --detailed[/cyan]  [dim](show all patterns)[/dim]",
            border_style="dim"
        ))
        console.print()
