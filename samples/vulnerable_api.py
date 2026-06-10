from fastapi import FastAPI, Depends

app = FastAPI()

# Simulação de banco de dados
class Database:
    def get(self, item_id):
        return {"item_id": item_id, "owner_id": 42, "secret_data": "Confidencial"}

db = Database()

# VULNERÁVEL: O parâmetro 'item_id' (Source) é passado diretamente para o db.get() (Sink)
# sem verificar se o usuário autenticado é o proprietário do recurso.
@app.get("/items/{item_id}")
def read_item(item_id: int):
    return db.get(item_id)
