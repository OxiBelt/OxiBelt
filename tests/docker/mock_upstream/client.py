import argparse
import ssl
import sys
import urllib.error
import urllib.request


def main() -> int:
  parser = argparse.ArgumentParser()
  parser.add_argument("--url", required=True)
  parser.add_argument("--host", required=True)
  parser.add_argument("--ca-file")
  parser.add_argument("--insecure", action="store_true")
  parser.add_argument("--timeout", type=float, default=5.0)
  args = parser.parse_args()

  if args.insecure:
    context = ssl._create_unverified_context()
  elif args.ca_file:
    context = ssl.create_default_context(cafile=args.ca_file)
  else:
    context = ssl.create_default_context()

  request = urllib.request.Request(args.url, headers={"Host": args.host})

  try:
    with urllib.request.urlopen(request, context=context, timeout=args.timeout) as response:
      sys.stdout.write(response.read().decode("utf-8"))
      return 0
  except urllib.error.HTTPError as error:
    sys.stdout.write(error.read().decode("utf-8"))
    return 1


if __name__ == "__main__":
  raise SystemExit(main())
