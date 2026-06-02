const { app, host, port, getDbContext } = require("./app");

getDbContext()
  .then(() => {
    app.listen(port, host, () => {
      console.log(`Server running at http://${host}:${port}`);
    });
  })
  .catch((error) => {
    console.error("Failed to start server");
    console.error(error);
    process.exit(1);
  });
