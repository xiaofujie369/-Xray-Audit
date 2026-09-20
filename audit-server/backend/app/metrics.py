from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .models import Counter


def increment(db, name, amount=1):
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    statement = insert(Counter).values(name=name, value=amount)
    db.execute(
        statement.on_conflict_do_update(index_elements=[Counter.name], set_={"value": Counter.value + amount})
    )
