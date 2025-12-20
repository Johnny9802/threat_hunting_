"""CLI interface for threat hunting playbook management."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from src.ai_assistant import AIAssistant
from src.exporter import QueryExporter
from src.mitre_mapping import MitreMapper
from src.parser import PlaybookParser
from src.search import PlaybookSearch

console = Console()
parser = PlaybookParser()
search = PlaybookSearch(parser)
exporter = QueryExporter()
ai = AIAssistant()
mitre = MitreMapper()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Threat Hunting Playbook - AI-powered CLI for managing threat hunting playbooks.

    A comprehensive tool for security analysts and threat hunters to search,
    view, export, and get AI-powered insights on threat hunting playbooks.
    """
    pass


@cli.group()
def search_group():
    """Search and list playbooks."""
    pass


@cli.command("search")
@click.argument("keyword", required=False)
@click.option("--technique", "-t", help="MITRE technique ID (e.g., T1566)")
@click.option("--tactic", help="MITRE tactic name (e.g., initial-access)")
@click.option("--tag", help="Tag to filter by")
@click.option(
    "--severity", "-s", type=click.Choice(["critical", "high", "medium", "low"])
)
def search_playbooks(keyword, technique, tactic, tag, severity):
    """Search playbooks by keyword, technique, tactic, tag, or severity.

    Examples:
        hunt search phishing
        hunt search --technique T1566
        hunt search --tactic initial-access
        hunt search --tag email --severity high
    """
    try:
        results = search.search(
            query=keyword,
            technique=technique,
            tactic=tactic,
            tag=tag,
            severity=severity,
        )

        if not results:
            console.print("[yellow]No playbooks found matching criteria[/yellow]")
            return

        # Display results in a table
        table = Table(title=f"Found {len(results)} Playbook(s)", box=box.ROUNDED)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("Technique", style="magenta")
        table.add_column("Tactic", style="blue")
        table.add_column("Severity", style="red")

        severity_colors = {
            "critical": "bright_red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }

        for pb in results:
            sev = pb.get("severity", "unknown")
            sev_colored = f"[{severity_colors.get(sev, 'white')}]{sev.upper()}[/]"

            table.add_row(
                pb.get("id", "N/A"),
                pb.get("name", "N/A"),
                pb.get("technique", "N/A"),
                pb.get("tactic", "N/A"),
                sev_colored,
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


@cli.command("list")
def list_playbooks():
    """List all available playbooks.

    Example:
        hunt list
    """
    try:
        playbooks = search.list_all()

        if not playbooks:
            console.print("[yellow]No playbooks found[/yellow]")
            return

        table = Table(title=f"All Playbooks ({len(playbooks)})", box=box.ROUNDED)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("Technique", style="magenta")
        table.add_column("Severity", style="red")
        table.add_column("Tags", style="dim")

        severity_colors = {
            "critical": "bright_red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }

        for pb in playbooks:
            sev = pb.get("severity", "unknown")
            sev_colored = f"[{severity_colors.get(sev, 'white')}]{sev.upper()}[/]"
            tags = ", ".join(pb.get("tags", [])[:3])

            table.add_row(
                pb.get("id", "N/A"),
                pb.get("name", "N/A"),
                pb.get("technique", "N/A"),
                sev_colored,
                tags,
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


@cli.command("show")
@click.argument("playbook_id")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
def show_playbook(playbook_id, format):
    """Show detailed information about a playbook.

    Examples:
        hunt show PB-T1566-001
        hunt show PB-T1566-001 --format json
    """
    try:
        playbook = search.get_by_id(playbook_id)

        if format == "json":
            import json

            console.print_json(json.dumps(playbook, indent=2))
            return

        # Display as formatted text
        mitre_info = playbook.get("mitre", {})
        technique_id = mitre_info.get("technique", "N/A")

        # Header
        header = f"[bold cyan]{playbook.get('name')}[/bold cyan]\n"
        header += f"[dim]{playbook.get('description')}[/dim]"
        console.print(
            Panel(header, title=f"[bold]{playbook_id}[/bold]", border_style="cyan")
        )

        # Metadata
        console.print("\n[bold]Metadata[/bold]")
        meta_table = Table(show_header=False, box=None, padding=(0, 2))
        meta_table.add_column("Key", style="cyan")
        meta_table.add_column("Value", style="white")

        meta_table.add_row("MITRE Technique", mitre.format_mitre_info(technique_id))
        meta_table.add_row("Severity", playbook.get("severity", "N/A").upper())
        meta_table.add_row("Author", playbook.get("author", "N/A"))
        meta_table.add_row("Created", playbook.get("created", "N/A"))

        if playbook.get("updated"):
            meta_table.add_row("Updated", playbook["updated"])

        if playbook.get("tags"):
            meta_table.add_row("Tags", ", ".join(playbook["tags"]))

        console.print(meta_table)

        # Hunt Hypothesis
        if playbook.get("hunt_hypothesis"):
            console.print("\n[bold]Hunt Hypothesis[/bold]")
            console.print(Panel(playbook["hunt_hypothesis"], border_style="blue"))

        # Data Sources
        if playbook.get("data_sources"):
            console.print("\n[bold]Data Sources[/bold]")
            for ds in playbook["data_sources"]:
                console.print(f"  • {ds}")

        # Queries
        queries_content = playbook.get("queries_content", {})
        if queries_content:
            console.print("\n[bold]Detection Queries[/bold]")
            for siem, query in queries_content.items():
                console.print(f"\n[cyan]{siem.upper()}:[/cyan]")

                # Syntax highlighting
                lang_map = {"splunk": "sql", "elastic": "sql", "sigma": "yaml"}
                syntax = Syntax(
                    query,
                    lang_map.get(siem, "text"),
                    theme="monokai",
                    line_numbers=True,
                )
                console.print(syntax)

        # Investigation Steps
        if playbook.get("investigation_steps"):
            console.print("\n[bold]Investigation Steps[/bold]")
            for i, step in enumerate(playbook["investigation_steps"], 1):
                console.print(f"  {i}. {step}")

        # False Positives
        if playbook.get("false_positives"):
            console.print("\n[bold yellow]False Positives[/bold yellow]")
            for fp in playbook["false_positives"]:
                console.print(f"  ⚠ {fp}")

        # IOCs
        if playbook.get("iocs"):
            console.print("\n[bold red]Indicators of Compromise[/bold red]")
            ioc_table = Table(box=box.SIMPLE)
            ioc_table.add_column("Type", style="cyan")
            ioc_table.add_column("Value", style="red")
            ioc_table.add_column("Context", style="dim")

            for ioc in playbook["iocs"]:
                ioc_table.add_row(
                    ioc.get("type", "N/A"),
                    ioc.get("value", "N/A"),
                    ioc.get("context", ""),
                )

            console.print(ioc_table)

        # References
        if playbook.get("references"):
            console.print("\n[bold]References[/bold]")
            for ref in playbook["references"]:
                console.print(f"  • {ref}")

    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Playbook {playbook_id} not found")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


@cli.command("export")
@click.argument("playbook_id")
@click.option(
    "--siem",
    "-s",
    required=True,
    type=click.Choice(["splunk", "elastic", "sigma"]),
    help="Target SIEM platform",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
def export_query(playbook_id, siem, output):
    """Export a query for a specific SIEM platform.

    Examples:
        hunt export PB-T1566-001 --siem splunk
        hunt export PB-T1566-001 --siem elastic --output query.kql
    """
    try:
        playbook = search.get_by_id(playbook_id)

        output_path = Path(output) if output else None
        query = exporter.export_query(playbook, siem, output_path)

        if output_path:
            console.print(f"[green]✓[/green] Query exported to: {output_path}")
        else:
            console.print(f"\n[bold cyan]{siem.upper()} Query:[/bold cyan]\n")
            lang_map = {"splunk": "sql", "elastic": "sql", "sigma": "yaml"}
            syntax = Syntax(
                query, lang_map.get(siem, "text"), theme="monokai", line_numbers=True
            )
            console.print(syntax)

    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Playbook {playbook_id} not found")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


@cli.command("export-all")
@click.argument("playbook_id", required=False)
@click.option(
    "--siem",
    "-s",
    type=click.Choice(["splunk", "elastic", "sigma"]),
    help="Specific SIEM to export",
)
@click.option(
    "--output", "-o", type=click.Path(), default="./export", help="Output directory"
)
def export_all_queries(playbook_id, siem, output):
    """Export all queries for a playbook (or all playbooks) to a directory.

    Examples:
        hunt export-all PB-T1566-001 --output ./exports
        hunt export-all --siem splunk --output ./splunk-queries
    """
    try:
        output_dir = Path(output)
        output_dir.mkdir(parents=True, exist_ok=True)

        if playbook_id:
            # Export single playbook
            playbook = search.get_by_id(playbook_id)
            playbooks = [playbook]
        else:
            # Export all playbooks
            all_pbs = search.list_all()
            playbooks = [search.get_by_id(pb["id"]) for pb in all_pbs]

        total_exported = 0

        with console.status("[bold green]Exporting queries...") as status:
            for pb in playbooks:
                pb_id = pb.get("id")
                pb_dir = output_dir / pb_id

                if siem:
                    # Export specific SIEM
                    try:
                        ext_map = {"splunk": "spl", "elastic": "kql", "sigma": "yml"}
                        ext = ext_map.get(siem, "txt")
                        output_file = pb_dir / f"{siem}.{ext}"
                        exporter.export_query(pb, siem, output_file)
                        total_exported += 1
                    except ValueError:
                        continue
                else:
                    # Export all available SIEMs
                    exported = exporter.export_all_queries(pb, pb_dir)
                    total_exported += len(exported)

        console.print(
            f"[green]✓[/green] Exported {total_exported} queries to: {output_dir}"
        )

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


@cli.group()
def ai_group():
    """AI-powered playbook analysis and generation."""
    pass


@cli.command("ai")
@click.argument("subcommand")
@click.argument("args", nargs=-1)
@click.option("--target", help="Target environment for generation")
@click.option(
    "--siem", type=click.Choice(["splunk", "elastic", "sigma"]), help="Target SIEM"
)
def ai_commands(subcommand, args, target, siem):
    """AI assistant commands for threat hunting.

    Subcommands:
        explain PLAYBOOK_ID - Explain a playbook in detail
        ask "QUESTION" - Ask a free-form question
        suggest --found "FINDING" - Get investigation suggestions
        generate PLAYBOOK_ID --target ENV --siem SIEM - Generate variant

    Examples:
        hunt ai explain PB-T1566-001
        hunt ai ask "How do I detect mimikatz in Splunk?"
        hunt ai suggest --found "suspicious powershell execution"
        hunt ai generate PB-T1566-001 --target "Azure AD" --siem elastic
    """
    if not ai.is_available():
        console.print("[red]Error:[/red] AI Assistant not configured")
        console.print("Set GROQ_API_KEY or OPENAI_API_KEY in .env file")
        console.print("See .env.example for details")
        sys.exit(1)

    try:
        console.print(f"[dim]{ai.get_provider_info()}[/dim]\n")

        if subcommand == "explain":
            if not args:
                console.print("[red]Error:[/red] Playbook ID required")
                sys.exit(1)

            playbook_id = args[0]
            playbook = search.get_by_id(playbook_id)

            with console.status("[bold green]Generating explanation..."):
                explanation = ai.explain_playbook(playbook)

            console.print(
                Panel(
                    Markdown(explanation),
                    title=f"[bold]AI Explanation: {playbook_id}[/bold]",
                    border_style="green",
                )
            )

        elif subcommand == "ask":
            if not args:
                console.print("[red]Error:[/red] Question required")
                sys.exit(1)

            question = " ".join(args)

            with console.status("[bold green]Thinking..."):
                answer = ai.ask_question(question)

            console.print(
                Panel(
                    Markdown(answer),
                    title="[bold]AI Response[/bold]",
                    border_style="blue",
                )
            )

        elif subcommand == "suggest":
            # Look for --found in original args
            if "--found" in sys.argv:
                idx = sys.argv.index("--found")
                if idx + 1 < len(sys.argv):
                    finding = sys.argv[idx + 1]
                else:
                    console.print(
                        "[red]Error:[/red] Finding description required after --found"
                    )
                    sys.exit(1)
            else:
                console.print(
                    '[red]Error:[/red] Use --found "description" to provide finding'
                )
                sys.exit(1)

            with console.status("[bold green]Analyzing finding..."):
                suggestions = ai.suggest_next_steps(finding)

            console.print(
                Panel(
                    Markdown(suggestions),
                    title="[bold]Investigation Suggestions[/bold]",
                    border_style="yellow",
                )
            )

        elif subcommand == "generate":
            if not args:
                console.print("[red]Error:[/red] Playbook ID required")
                sys.exit(1)

            if not target or not siem:
                console.print(
                    "[red]Error:[/red] --target and --siem required for generate"
                )
                sys.exit(1)

            playbook_id = args[0]
            playbook = search.get_by_id(playbook_id)

            with console.status(f"[bold green]Generating variant for {target}..."):
                variant = ai.generate_variant(playbook, target, siem)

            console.print(
                Panel(
                    Markdown(variant),
                    title=f"[bold]Generated Variant: {target} ({siem})[/bold]",
                    border_style="magenta",
                )
            )

        else:
            console.print(f"[red]Error:[/red] Unknown subcommand: {subcommand}")
            console.print("Valid subcommands: explain, ask, suggest, generate")
            sys.exit(1)

    except FileNotFoundError:
        console.print(f"[red]Error:[/red] Playbook not found")
        sys.exit(1)
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
