from django.db.models.expressions import RawSQL
from django.contrib.auth.models import User

User.objects.annotate(val=RawSQL('secure', []))
User.objects.annotate(val=RawSQL('nosecure', []))
User.objects.annotate(val=RawSQL('nosecure', []))
raw = '"username") AS "val" FROM "auth_user" WHERE "username"="admin" --'
User.objects.annotate(val=RawSQL(raw, []))
raw = '"username") AS "val" FROM "auth_user"' \
      ' WHERE "username"="admin" OR 1=%s --'
User.objects.annotate(val=RawSQL(raw, [0]))
