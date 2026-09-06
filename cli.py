"""Command-line interface for the FAST IOC collector."""

import argparse
import logging
import os
from typing import Optional, Sequence

from core import db, exporter, fetchers, normalizer, wazuh_export

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def run_init_db() -> bool:
    db.init_database()
    print("✓ Verilənlər bazası hazırdır.")
    return True


def run_fetch() -> bool:
    """Fetch/normalize/store feeds and fail if every provider returned zero data."""
    db.init_database()
    print("📡 Feed-lərdən məlumat çəkilir...")
    raw_feeds = fetchers.fetch_all_feeds()
    raw_total = 0
    for feed_name, iocs in raw_feeds.items():
        raw_total += len(iocs)
        print(f"  • {feed_name}: {len(iocs)} xam qeyd")

    if raw_total == 0:
        print("✗ Heç bir feed məlumat qaytarmadı; köhnə IOC datası üzərinə uğurlu refresh kimi yazılmayacaq.")
        return False

    print("\n🔄 Normallaşdırılır...")
    normalized = normalizer.normalize_all(raw_feeds)
    print(f"  • Cəmi {len(normalized)} IOC normallaşdırıldı")
    if not normalized:
        print("✗ Feed məlumatı gəldi, amma heç bir IOC normallaşdırıla bilmədi.")
        return False

    print("\n💾 Bazaya yazılır (dedup + scoring avtomatik)...")
    processed = db.insert_batch(normalized)
    print(f"  • {processed} IOC emal edildi")
    if processed == 0:
        print("✗ Heç bir normallaşdırılmış IOC bazaya yazıla bilmədi.")
        return False

    print(f"\n✓ Tamamlandı. Bazadakı unikal IOC sayı: {db.get_count()}")
    return True


def run_export(fmt: str) -> bool:
    iocs = db.get_all_iocs()
    if not iocs:
        print("✗ Bazada IOC yoxdur. Əvvəlcə --fetch işə sal.")
        return False

    if fmt == "csv":
        ok = exporter.export_to_csv(iocs)
        print(f"{'✓' if ok else '✗'} CSV export: sample_output/ioc_export.csv ({len(iocs)} IOC)")
        return ok
    if fmt == "json":
        ok = exporter.export_to_json(iocs)
        print(f"{'✓' if ok else '✗'} JSON export: sample_output/ioc_export.json ({len(iocs)} IOC)")
        return ok
    if fmt == "both":
        ok = exporter.export_both(iocs)
        print(f"{'✓' if ok else '✗'} CSV+JSON export: sample_output/ ({len(iocs)} IOC)")
        return ok
    if fmt == "wazuh":
        stats = wazuh_export.get_export_stats(iocs)
        ok = wazuh_export.export_to_cdb_list(iocs)
        path = os.path.join("sample_output", wazuh_export.DEFAULT_CDB_FILENAME)
        usable = ok and stats["exported"] > 0 and os.path.isfile(path) and os.path.getsize(path) > 0
        print(
            f"{'✓' if usable else '✗'} Wazuh CDB list export: {path} "
            f"({stats['exported']}/{stats['ip_type']} etibarlı IPv4/CIDR, cəmi {stats['total']} IOC-dan)"
        )
        if ok and not usable:
            print("✗ Wazuh CDB siyahısı boşdur; Manager-ə boş threat list göndərilməyəcək.")
        return usable

    print(f"✗ Naməlum format: {fmt!r}")
    return False


def run_show() -> bool:
    iocs = db.get_all_iocs()
    if not iocs:
        print("⚠️ Bazada IOC yoxdur.")
        return True
    print(f"\n{'IOC Value':<45} {'Type':<8} {'Feed':<25} {'Score':<6} {'Last Seen'}")
    print("-" * 110)
    for ioc in iocs:
        print(
            f"{str(ioc.get('ioc_value', ''))[:43]:<45} "
            f"{ioc.get('ioc_type', ''):<8} "
            f"{str(ioc.get('source_feed', ''))[:23]:<25} "
            f"{ioc.get('confidence_score', 0):<6} "
            f"{ioc.get('last_seen', '')}"
        )
    print(f"\nCəmi: {len(iocs)} IOC")
    return True


def run_count() -> bool:
    print(f"Bazadakı toplam IOC sayı: {db.get_count()}")
    return True


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="FAST IOC Collector")
    parser.add_argument("--init-db", action="store_true", help="Verilənlər bazasını yarat")
    parser.add_argument("--fetch", action="store_true", help="Bütün feed-lərdən yığ")
    parser.add_argument("--export", choices=["csv", "json", "both", "wazuh"], help="Export formatı")
    parser.add_argument("--show", action="store_true", help="IOC-ları göstər")
    parser.add_argument("--count", action="store_true", help="IOC sayını göstər")
    args = parser.parse_args(argv)

    if not any([args.init_db, args.fetch, args.export, args.show, args.count]):
        parser.print_help()
        return 0

    ok = True
    if args.init_db:
        ok = run_init_db() and ok
    if args.fetch:
        ok = run_fetch() and ok
    if args.export:
        ok = run_export(args.export) and ok
    if args.show:
        ok = run_show() and ok
    if args.count:
        ok = run_count() and ok
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
