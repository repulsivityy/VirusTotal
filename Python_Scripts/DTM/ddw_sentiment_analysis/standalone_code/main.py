import argparse
import json
import os
import sys

from ddw_client import GTIDDWClient
from analyzer import DDWSentimentAnalyzer

def print_banner():
    print("=" * 70)
    print(" 🕵️ GTI Deep & Dark Web (DDW) Contextual Sentiment Analyzer")
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(
        description="Fetch GTI Dark Web posts with configurable context window (+/- N chats) and run contextual analysis."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--id", help="Dark Web Communication ID to inspect and analyze")
    group.add_argument("--author", help="Search and list recent posts by this author")
    group.add_argument("--channel", help="Search and inspect recent posts and info for a channel")

    parser.add_argument(
        "--window",
        type=int,
        default=10,
        help="Number of messages before and after target post (default: 10, configurable up to 40)"
    )
    parser.add_argument(
        "--profile-author",
        action="store_true",
        help="Search GTI for author's historical footprint across underground channels and forums"
    )
    parser.add_argument(
        "--author-history-limit",
        type=int,
        default=10,
        help="Number of historical posts to query for author profiling (default: 10, max: 25)"
    )
    parser.add_argument("--output", help="Optional path to save full JSON output (ready for BQ/SQL)")
    parser.add_argument("--dry-run", action="store_true", help="Assemble context window and prompt without calling Gemini LLM")
    parser.add_argument("--gti-key", help="GTI API Key (defaults to GTI_APIKEY env var)")
    parser.add_argument("--gemini-key", help="Gemini API Key (defaults to GEMINI_API_KEY env var)")
    parser.add_argument("--model", default="gemini-3.8-flash", help="Gemini model to use (default: gemini-3.8-flash)")

    args = parser.parse_args()
    print_banner()

    # Upfront check for GTI API Key (required for all modes)
    gti_key = args.gti_key or os.getenv("GTI_APIKEY") or os.getenv("VT_APIKEY")
    if not gti_key:
        print("\n❌ Configuration Error: Missing GTI API Key.")
        print("   Please set the GTI_APIKEY environment variable:")
        print("     export GTI_APIKEY=\"your_gti_api_key\"")
        print("   Or provide it via CLI with: --gti-key <KEY>\n")
        sys.exit(1)

    # Upfront check for Gemini API Key (required when analyzing a post without --dry-run)
    gemini_key = args.gemini_key or os.getenv("GEMINI_API_KEY") or os.getenv("GEMINI_APIKEY")
    if args.id and not args.dry_run and not gemini_key:
        print("\n❌ Configuration Error: Missing Gemini API Key.")
        print("   Please set the GEMINI_API_KEY environment variable:")
        print("     export GEMINI_API_KEY=\"your_gemini_api_key\"")
        print("   Or provide it via CLI with: --gemini-key <KEY>")
        print("   (Tip: pass --dry-run to fetch and inspect context without calling Gemini)\n")
        sys.exit(1)

    try:
        client = GTIDDWClient(api_key=gti_key)
    except ValueError as e:
        print(f"\n❌ Configuration Error: {e}")
        sys.exit(1)

    # Mode 1: Search by author
    if args.author:
        print(f"\n🔍 Searching GTI DDW communications by author: '{args.author}'...")
        try:
            posts = client.search_communications_by_author(args.author, limit=10)
        except Exception as e:
            print(f"❌ Error querying GTI API: {e}")
            sys.exit(1)

        if not posts:
            print("No communications found for this author.")
            return

        print(f"\nFound {len(posts)} recent communications:\n")
        for i, post in enumerate(posts, 1):
            p_id = post.get("id")
            attrs = post.get("attributes", {})
            orig = (attrs.get("content") or "").strip()
            trans = (attrs.get("content_translated") or "").strip()
            print(f"[{i}] ID: {p_id} | Type: {attrs.get('communication_type')} | Date: {attrs.get('timestamp')}")
            if trans and orig and trans != orig:
                print(f"    Translated: {trans[:150]}...")
                print(f"    Original  : {orig[:150]}...\n")
            else:
                text = trans or orig or (attrs.get("subject") or "")
                print(f"    Text: {text[:200]}...\n")

        print("💡 To analyze one of these posts in its context window, rerun with:")
        print(f"   python main.py --id <POST_ID> --window {args.window}\n")
        return

    # Mode 2: Inspect channel
    if args.channel:
        print(f"\n🔍 Fetching sample posts from channel: '{args.channel}'...")
        try:
            sample_posts = client.search_communications_by_channel(args.channel, limit=5)
        except Exception as e:
            print(f"❌ Error querying GTI API: {e}")
            sys.exit(1)

        if not sample_posts:
            print("No communications found for this channel.")
            return

        print(f"\nSample recent posts in '{args.channel}':\n")
        for i, post in enumerate(sample_posts, 1):
            p_id = post.get("id")
            attrs = post.get("attributes", {})
            orig = (attrs.get("content") or "").strip()
            trans = (attrs.get("content_translated") or "").strip()
            print(f"[{i}] ID: {p_id} | Author: {attrs.get('author')}")
            if trans and orig and trans != orig:
                print(f"    Translated: {trans[:150]}...")
                print(f"    Original  : {orig[:150]}...\n")
            else:
                text = trans or orig
                print(f"    Text: {text[:200]}...\n")
        return

    # Mode 3: Contextual Sentiment Analysis for a specific Communication ID
    comm_id = args.id
    window = max(1, min(args.window, 40))
    profile_author = args.profile_author
    author_limit = max(1, min(args.author_history_limit, 25))
    profile_msg = f" (with author profiling limit: {author_limit})" if profile_author else ""
    print(f"\n📥 Fetching target post '{comm_id}' with +/- {window} context window{profile_msg}...")

    try:
        context_bundle = client.get_context_window(
            comm_id,
            window_size=window,
            profile_author=profile_author,
            author_history_limit=author_limit
        )
    except Exception as e:
        print(f"❌ Failed to fetch context window: {e}")
        sys.exit(1)

    target = context_bundle["target"]
    ch = context_bundle["channel_or_thread"]
    prev_chats = context_bundle["context"]["previous_messages"]
    next_chats = context_bundle["context"]["next_messages"]
    footprint = context_bundle.get("author_footprint")
    retrieval_errors = context_bundle.get("retrieval_errors", [])

    print("\n" + "-" * 70)
    print(f"📌 Container Name : {ch.get('name') or 'N/A'}")
    print(f"📌 Container Bio  : {ch.get('description') or 'N/A'}")
    print(f"📌 Container URL  : {ch.get('url') or 'N/A'}")
    print("-" * 70)

    # Display Author Footprint summary if profiled
    if footprint:
        hist_count = footprint.get('total_historical_posts_retrieved', 0)
        u_plat = footprint.get('unique_platforms_count', 0)
        plat_str = ', '.join(footprint.get('platforms_observed', [])) or 'None'
        copy_rate = int(footprint.get('copypasta_broadcast_rate', 0.0) * 100)
        span = footprint.get('activity_span_days', 0.0)
        print(f"👤 Author Footprint : {hist_count} historical post(s) across {u_plat} platform(s)")
        print(f"👤 Platforms Seen   : {plat_str}")
        print(f"👤 Broadcast Dupl.  : {copy_rate}% copypasta rate | Active span: {span} days")
        print("-" * 70)

    print(f"⏮️  Preceding messages retrieved : {len(prev_chats)} messages")
    print(f"🎯 Target Timestamp             : {target.get('timestamp_iso')} (Epoch: {target.get('timestamp')})")
    print(f"🎯 Target Author                : {target.get('author')}")

    target_orig = (target.get("original_text") or "").strip()
    target_trans = (target.get("translated_text") or "").strip()
    if target_orig and target_trans and target_orig != target_trans:
        print(f"🎯 Target (Translated)          : {target_trans[:200]}")
        print(f"🎯 Target (Original Language)   : {target_orig[:200]}")
    else:
        print(f"🎯 Target Post Preview          : {(target.get('text') or '')[:200]}")

    print(f"⏭️  Subsequent messages retrieved: {len(next_chats)} messages")
    print("-" * 70)

    if retrieval_errors:
        print("\n⚠️  Retrieval Warnings / Incomplete Context:")
        for err in retrieval_errors:
            print(f"   • {err}")
        print("-" * 70)

    analyzer = DDWSentimentAnalyzer(api_key=gemini_key, model=args.model)

    if args.dry_run:
        print("\n🔎 DRY RUN ENABLED — Assembled Prompt Preview:")
        print("=" * 70)
        print(analyzer.build_analysis_prompt(context_bundle))
        print("=" * 70)
        return

    print(f"\n🧠 Running LLM Reasoning using {args.model}...")
    analysis_result = analyzer.analyze(context_bundle)

    # Combine for unified record (ready for BigQuery/SQL)
    from datetime import datetime, timezone
    final_record = {
        "communication_id": comm_id,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "channel": ch,
        "target_post": target,
        "author_footprint": footprint,
        "context_window": {
            "window_size_configured": window,
            "previous_count": len(prev_chats),
            "next_count": len(next_chats),
            "previous_messages": prev_chats,
            "next_messages": next_chats
        },
        "retrieval_errors": retrieval_errors,
        "analysis": analysis_result
    }

    print("\n📊 ANALYSIS RESULT:")
    print("=" * 70)
    print(json.dumps(analysis_result, indent=2, ensure_ascii=False))
    print("=" * 70)

    # Highlight CTI Summary
    threat = analysis_result.get("threat_and_supply_chain", {})
    sentiment = analysis_result.get("community_sentiment_and_reaction", {})
    rec = analysis_result.get("investigative_recommendation")
    if threat:
        ep = threat.get("estimative_probability", {})
        ep_range = ep.get('probability_range')
        range_str = f" [{ep_range}]" if ep_range and ep_range != "N/A" else ""
        ep_str = f"{ep.get('level')}{range_str}" if ep else "N/A"
        print("\n🎯 CTI THREAT & SENTIMENT HIGHLIGHTS:")
        print(f"   • Intent / Category    : {threat.get('intent_category')}")
        print(f"   • Estimative Prob.     : {ep_str} (Actionable: {threat.get('is_actionable_threat')})")
        if ep.get("criteria_matched"):
            print(f"   • Criteria Matched     : {' | '.join(ep.get('criteria_matched'))}")
        if ep.get("rationale"):
            print(f"   • Prob. Rationale      : {ep.get('rationale')}")
        if threat.get("explicitly_claimed_actor"):
            print(f"   • Claimed Threat Actor : {threat.get('explicitly_claimed_actor')}")
        if threat.get("targeted_entities"):
            print(f"   • Targeted Entities    : {', '.join(threat.get('targeted_entities'))}")
        if threat.get("targeted_sectors"):
            print(f"   • Targeted Sectors     : {', '.join(threat.get('targeted_sectors'))}")
        if threat.get("targeted_technologies"):
            print(f"   • Targeted Tech        : {', '.join(threat.get('targeted_technologies'))}")
        if sentiment:
            print(f"   • Community Sentiment  : {sentiment.get('reaction_status')} (Vouched: {sentiment.get('vouches_detected')}, Disputes: {sentiment.get('disputes_or_scam_warnings', False)})")
        if rec:
            print(f"   • Recommendation       : {rec}")
        disclaimer = analysis_result.get("analytic_scope_disclaimer")
        if disclaimer:
            print(f"   ℹ️  Disclaimer          : {disclaimer}")
        print("-" * 70)

    if args.output:
        out_path = os.path.abspath(args.output)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(final_record, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Saved full context + analysis record to: {out_path}")

if __name__ == "__main__":
    main()
