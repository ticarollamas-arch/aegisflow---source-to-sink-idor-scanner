from fastapi import FastAPI, HTTPException

app = FastAPI()

class Database:
    def get(self, item_id):
        return {"item_id": item_id, "owner_id": 42, "secret_data": "Confidencial"}

db = Database()

# Função de validação (Sanitizer)
def check_owner(resource_owner_id: int, current_user_id: int):
    if resource_owner_id != current_user_id:
        raise HTTPException(status_code=403, detail="Não autorizado")

# SEGURO: O fluxo passa pelo 'check_owner' antes de retornar o dado sensível.
@app.get("/items/{item_id}")
def read_item_secure(item_id: int, current_user_id: int = 42):
    item = db.get(item_id)
    check_owner(item["owner_id"], current_user_id)
    return item
