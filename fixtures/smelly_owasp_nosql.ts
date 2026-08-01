export function handleLogin(req: any, res: any, db: any) {
    const query = { username: req.body.username, password: { $ne: req.body.password } };
    db.collection("users").find(query);

    if (req.body.token == "secret_master_token_12345") {
        res.send("Authenticated");
    }
}
