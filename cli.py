"""CLI for running collectors and persisting results to SQLite."""

import typer
from rich.console import Console
from rich.table import Table

from collectors.nvd_cve import fetch_cves, iter_vulnerabilities
from collectors.sans_isc_xml import fetch_feed, parse_items
from db import count_advisories, init_db, list_advisories, save_advisories
from parsers.mapper import MappingError
from parsers.normalize import cve_to_advisory, rss_item_to_advisory


app = typer.Typer(help="Security advisory collector and parser")
console = Console()

DEFAULT_DB = "advisories.db"


@app.command()
def fetch_nvd(
    db: str = typer.Option(DEFAULT_DB, "--db", "-d", help="SQLite database path"),
    results_per_page: int = typer.Option(20, "--limit", "-l", help="Results per page"),
    start_index: int = typer.Option(0, "--start", "-s", help="Start index"),
) -> None:
    """Fetch NVD CVEs and save to database."""
    console.print("[cyan]Fetching NVD CVE API...[/cyan]")

    try:
        init_db(db)
        payload = fetch_cves(results_per_page=results_per_page, start_index=start_index)
        cves = list(iter_vulnerabilities(payload))
        console.print(f"[green]✓[/green] Retrieved {len(cves)} CVE records")

        advisories = []
        errors = []
        for cve in cves:
            try:
                advisory = cve_to_advisory(cve)
                advisories.append(advisory)
            except MappingError as e:
                errors.append((cve.get("id", "unknown"), str(e)))

        if advisories:
            save_advisories(advisories, db)
            console.print(
                f"[green]✓[/green] Saved {len(advisories)} advisories to {db}"
            )

        if errors:
            console.print(f"[yellow]⚠[/yellow] {len(errors)} records skipped:")
            for cve_id, error in errors:
                console.print(f"  {cve_id}: {error}")

    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}", style="bold red")
        raise typer.Exit(code=1) from e


@app.command()
def fetch_sans(
    db: str = typer.Option(DEFAULT_DB, "--db", "-d", help="SQLite database path"),
) -> None:
    """Fetch SANS ISC RSS feed and save to database."""
    console.print("[cyan]Fetching SANS ISC RSS feed...[/cyan]")

    try:
        init_db(db)
        xml_text = fetch_feed()
        items = parse_items(xml_text)
        console.print(f"[green]✓[/green] Parsed {len(items)} RSS items")

        advisories = []
        errors = []
        for item in items:
            try:
                advisory = rss_item_to_advisory(item)
                advisories.append(advisory)
            except MappingError as e:
                item_id = item.get("guid", "unknown")
                errors.append((item_id, str(e)))

        if advisories:
            save_advisories(advisories, db)
            console.print(
                f"[green]✓[/green] Saved {len(advisories)} advisories to {db}"
            )

        if errors:
            console.print(f"[yellow]⚠[/yellow] {len(errors)} records skipped:")
            for item_id, error in errors:
                console.print(f"  {item_id}: {error}")

    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}", style="bold red")
        raise typer.Exit(code=1) from e


@app.command()
def list_advisories_cmd(
    db: str = typer.Option(DEFAULT_DB, "--db", "-d", help="SQLite database path"),
    source: str = typer.Option(
        None, "--source", "-s", help="Filter by source (nvd_cve or sans_isc)"
    ),
    limit: int = typer.Option(10, "--limit", "-l", help="Max rows to display"),
) -> None:
    """List stored advisories."""
    try:
        advisories = list_advisories(db, source=source)

        if not advisories:
            console.print("[yellow]No advisories found[/yellow]")
            return

        # Show summary
        total = count_advisories(db)
        nvd_count = count_advisories(db, source="nvd_cve")
        sans_count = count_advisories(db, source="sans_isc")
        console.print(
            f"[cyan]Total: {total} | NVD: {nvd_count} | SANS: {sans_count}[/cyan]\n"
        )

        # Display table
        table = Table(title="Security Advisories")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Source", style="magenta")
        table.add_column("Title", style="green")
        table.add_column("Severity", style="yellow")
        table.add_column("CVSS", style="red")
        table.add_column("Published", style="blue")

        for advisory in advisories[:limit]:
            severity = advisory["severity"] or "—"
            cvss = f"{advisory['cvss_score']}" if advisory["cvss_score"] else "—"
            table.add_row(
                advisory["external_id"],
                advisory["source"],
                advisory["title"][:50],
                severity,
                cvss,
                advisory["published_at"][:10],
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}", style="bold red")
        raise typer.Exit(code=1) from e


@app.command()
def stats(
    db: str = typer.Option(DEFAULT_DB, "--db", "-d", help="SQLite database path"),
) -> None:
    """Show database statistics."""
    try:
        total = count_advisories(db)
        nvd_count = count_advisories(db, source="nvd_cve")
        sans_count = count_advisories(db, source="sans_isc")

        table = Table(title="Advisory Statistics")
        table.add_column("Source", style="cyan")
        table.add_column("Count", style="green", justify="right")

        table.add_row("NVD CVE", str(nvd_count))
        table.add_row("SANS ISC", str(sans_count))
        table.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]")

        console.print(table)

    except Exception as e:
        console.print(f"[red]✗ Error:[/red] {e}", style="bold red")
        raise typer.Exit(code=1) from e


if __name__ == "__main__":
    app()
