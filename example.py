#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
example.py - Usage example for nostr_poster

Running this file directly generates a fresh key pair and prints it.
Network publishing is only attempted when you set NSEC_OR_HEX (or replace
the placeholder below) with a real key; otherwise it is skipped, so the
example is safe to run without secrets.
"""

import nostr_poster as nostr

# Put your existing nsec or 64-char hex secret key here (keep it secret!).
# Leave empty to skip live network publishing.
NSEC_OR_HEX = ""


def main():
    # 1) Generate a new key pair (automatically backs up to keys_backup.txt)
    keys = nostr.create_keys()
    print("New keys:", keys["nsec"], keys["npub"])

    # 2) Customize the relay list
    nostr.RELAYS = ["wss://relay.damus.io", "wss://nos.lol"]

    # 3) Use an existing nsec (or 64-char hex key) if provided
    key = NSEC_OR_HEX or keys["nsec"]

    # 4) Publish a short note (kind 1)
    note = nostr.publish_note(key, "Hello from nostr_poster!")
    print("Note:", note["event_id"], note["results"])

    # 5) Publish a long-form article (kind 30023, NIP-23)
    article = nostr.publish_article(
        key,
        title="My First Article",
        content="# Hello\n\nThis is a markdown article.",
        summary="A short summary",
        image="",
        topics=["bitcoin", "nostr"],
    )
    print("Article:", article["event_id"], article["identifier"], article["results"])

    # 6) Delete a short note (NIP-09, kind 5)
    deletion = nostr.delete_event(key, note["event_id"], target_kind=1, reason="Testing deletion")
    print("Delete note:", deletion["event_id"], deletion["results"])

    # 7) Delete a long-form article (NIP-09, kind 5)
    deletion = nostr.delete_article(key, article["event_id"], article["identifier"], reason="Testing deletion")
    print("Delete article:", deletion["event_id"], deletion["results"])


if __name__ == "__main__":
    if not NSEC_OR_HEX:
        # Safe dry run: just show keys, do NOT hit the network
        keys = nostr.create_keys()
        print("Generated keys (backed up to keys_backup.txt):")
        print("  nsec:", keys["nsec"])
        print("  npub:", keys["npub"])
        print('Set NSEC_OR_HEX in example.py and run main() to publish for real.')
    else:
        main()
