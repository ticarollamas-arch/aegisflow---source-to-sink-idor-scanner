const express = require('express');
const app = express();
const db = require('./db');

// VULNERÁVEL: O parâmetro ':id' (Source) é usado diretamente na query do banco (Sink)
// sem qualquer validação de propriedade ou middleware de autorização.
app.get('/api/invoice/:id', async (req, res) => {
    const invoiceId = req.params.id;
    const invoice = await db.findOne({ id: invoiceId });
    res.json(invoice);
});
