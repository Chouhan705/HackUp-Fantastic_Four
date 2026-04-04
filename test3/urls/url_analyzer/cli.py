"""CLI for the URL analyzer."""
import asyncio
import json
import dataclasses
from enum import Enum

import click

from url_analyzer.analyzer import analyze
from url_analyzer.models import AnalysisConfig


class EnumEncoder(json.JSONEncoder):
    """JSON Encoder for Enums and Dataclasses."""
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        if dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)
        return super().default(obj)


@click.group()
def cli():
    """URL Analyzer CLI."""
    pass


@cli.command(name="analyze")
@click.argument("url")
@click.option("--json", "output_json", is_flag=True, help="Output raw JSON instead of coloured table")
@click.option("--no-redirects", is_flag=True, help="Skip redirect chain resolution")
@click.option("--no-tls", is_flag=True, help="Skip TLS certificate checks")
@click.option("--timeout", type=float, default=5.0, help="Per-request timeout in seconds [default: 5.0]")
@click.option("--gsb-key", help="Google Safe Browsing API key")
@click.option("--vt-key", help="VirusTotal API key")
@click.option("--maxmind", type=click.Path(exists=True, file_okay=False, dir_okay=True), help="Path to MaxMind GeoLite2 DB directory")
def analyze_cli(url, output_json, no_redirects, no_tls, timeout, gsb_key, vt_key, maxmind):
    """Analyze a URL for phishing and malware risks."""
    config = AnalysisConfig(
        resolve_redirects=not no_redirects,
        check_tls=not no_tls,
        timeout_seconds=timeout,
        google_api_key=gsb_key,
        virustotal_api_key=vt_key,
        maxmind_db_path=maxmind
    )
    
    result = asyncio.run(analyze(url, config))
    
    if output_json:
        click.echo(json.dumps(result, cls=EnumEncoder, indent=2))
        return
        
    # Coloured Table output
    verdict_colors = {
        "CLEAN": "green",
        "LOW RISK": "yellow",
        "SUSPICIOUS": "magenta",  # approximation for orange
        "DANGEROUS": "red"
    }
    
    color = verdict_colors.get(result.verdict, "white")
    click.secho(f"Verdict: {result.verdict}", fg=color, bold=True)
    click.echo(f"Score: {result.score}/100")
    
    if result.findings:
        click.echo("\nFindings:")
        click.echo(f"{'Severity':<10} | {'Category':<12} | {'Check':<25} | {'Evidence'}")
        click.echo("-" * 80)
        
        # Sort findings by severity weight
        sorted_findings = sorted(result.findings, key=lambda f: f.severity.value, reverse=True)
        
        for f in sorted_findings:
            sev_color = verdict_colors.get("DANGEROUS" if f.severity.value >= 40 else "SUSPICIOUS" if f.severity.value >= 25 else "LOW RISK" if f.severity.value >= 15 else "CLEAN", "white")
            click.secho(f"{f.severity.name:<10}", fg=sev_color, nl=False)
            click.echo(f" | {f.category.value:<12} | {f.check:<25} | {f.evidence[:60]}")
            
    click.echo(f"\nAnalysis time: {result.analysis_time_ms / 1000.:.2f}s")


if __name__ == "__main__":
    cli()
