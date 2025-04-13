from flask import Flask, render_template, request, redirect
from blockchain_databases import DBManager

app = Flask(__name__)
db_manager = DBManager()

@app.route("/")
def home():
    databases = db_manager.list_databases()
    return render_template("home.html", databases=databases)

@app.route("/tables/<db_name>")
def list_tables(db_name):
    tables = db_manager.list_tables(db_name)
    return render_template("tables.html", db_name=db_name, tables=tables)

@app.route("/table/<db_name>/<table_name>")
def view_table(db_name, table_name):
    rows = db_manager.get_all_records(db_name, table_name)
    return render_template("table_view.html", db_name=db_name, table_name=table_name, rows=rows)

@app.route("/delete/<db>/<table>/<int:rowid>")
def delete_row(db, table, rowid):
    db_manager.delete_record_by_id(db, table, rowid)
    return redirect(f"/table/{db}/{table}")

if __name__ == "__main__":
    app.run(port=1337, debug=True)
