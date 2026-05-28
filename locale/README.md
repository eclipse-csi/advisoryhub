# Translations

AdvisoryHub uses Django's built-in `gettext` machinery. To add a new
language code (or pull fresh strings into an existing one):

```sh
# Extract all marked strings from .py and templates into .po files.
python manage.py makemessages -l fr            # add French
python manage.py makemessages -l fr -d djangojs  # if you ship JS strings

# After editing locale/<code>/LC_MESSAGES/django.po, compile to .mo:
python manage.py compilemessages
```

Marked strings live in two shapes:

- **Templates**: `{% load i18n %}` once at the top, then
  `{% translate "Sign in" %}` and `{% blocktranslate %}…{% endblocktranslate %}`.
- **Python**: `from django.utils.translation import gettext_lazy as _`
  and wrap user-facing strings as `_("…")`. Use `gettext_lazy` (not
  plain `gettext`) for module-level strings — model verbose_names,
  form labels, choice labels — so the resolution happens at request
  time.

The currently-marked strings are deliberately the user-facing chrome
(navbar, page titles, headline buttons). Internal admin views,
machine-to-machine API responses, and audit log action codes are NOT
translated — they're for operators, and translating them would only
add work.

`locale/<code>/LC_MESSAGES/django.{po,mo}` files are generated; the
`.po` files are checked in (the source of truth for translators), the
`.mo` files are built at deploy time by `compilemessages`.
