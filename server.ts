import _http from "http";
import _url from "url";
import _fs from "fs";
import _express from "express";
import _dotenv from "dotenv";
import _cors from "cors";
import _fileUpload from "express-fileupload";
import _cloudinary, { UploadApiResponse } from "cloudinary";
import _streamifier from "streamifier";

import _bcryptjs from "bcryptjs";
import _jwt from "jsonwebtoken";

// Lettura delle password e parametri fondamentali
_dotenv.config({ path: ".env" });

// Configurazione Cloudinary
_cloudinary.v2.config({
  cloud_name: process.env.cloud_name,
  api_key: process.env.api_key,
  api_secret: process.env.api_secret,
});

// Variabili relative a MongoDB ed Express
import { MongoClient, ObjectId } from "mongodb";
import { error } from "console";
import { clearLine } from "readline";
import { env } from "process";
const DBNAME = process.env.DBNAME;
const connectionString: string = process.env.connectionStringAtlas;
const app = _express();

// Creazione ed avvio del server
// app è il router di Express, si occupa di tutta la gestione delle richieste http
const PORT: number = parseInt(process.env.PORT);
let paginaErrore;
const server = _http.createServer(app);
// Il secondo parametro facoltativo ipAddress consente di mettere il server in ascolto su una delle interfacce della macchina, se non lo metto viene messo in ascolto su tutte le interfacce (3 --> loopback e 2 di rete)
server.listen(PORT, () => {
  init();
  console.log(`Il Server è in ascolto sulla porta ${PORT}`);
});

function init() {
  _fs.readFile("./static/error.html", function (err, data) {
    if (err) {
      paginaErrore = `<h1>Risorsa non trovata</h1>`;
    } else {
      paginaErrore = data.toString();
    }
  });
}

//********************************************************************************************//
// Routes middleware
//********************************************************************************************//

// 1. Request log
app.use("/", (req: any, res: any, next: any) => {
  console.log(`-----> ${req.method}: ${req.originalUrl}`);
  next();
});

// 2. Gestione delle risorse statiche
// .static() è un metodo di express che ha già implementata la firma di sopra. Se trova il file fa la send() altrimenti fa la next()
app.use("/", _express.static("./static"));

// 3. Lettura dei parametri POST di req["body"] (bodyParser)
// .json() intercetta solo i parametri passati in json nel body della http request
app.use("/", _express.json({ limit: "50mb" }));
// .urlencoded() intercetta solo i parametri passati in urlencoded nel body della http request
app.use("/", _express.urlencoded({ limit: "50mb", extended: true }));

// 4. Aggancio dei parametri del FormData e dei parametri scalari passati dentro il FormData
// Dimensione massima del file = 10 MB
app.use("/", _fileUpload({ limits: { fileSize: 10 * 1024 * 1024 } }));

// 5. Log dei parametri GET, POST, PUT, PATCH, DELETE
app.use("/", (req: any, res: any, next: any) => {
  if (Object.keys(req["query"]).length > 0) {
    console.log(`       ${JSON.stringify(req["query"])}`);
  }
  if (Object.keys(req["body"]).length > 0) {
    console.log(`       ${JSON.stringify(req["body"])}`);
  }
  next();
});

// 6. Controllo degli accessi tramite CORS
const corsOptions = {
  origin: function (origin, callback) {
    return callback(null, true);
  },
  credentials: true,
};
app.use("/", _cors(corsOptions));

//*********************************************************************************************//
//LOGIN
//*********************************************************************************************//
app.post("/api/login", async (req: any, res: any) => {
  let username = req.body.username;
  let password = req.body.password;

  const client = new MongoClient(connectionString);
  await client.connect();
  const collection = client.db(DBNAME).collection("utenti");

  let rq = collection.findOne(
    { username: username },
    { projection: { username: 1, password: 1 } }
  );
  rq.then((dbUser: any) => {
    if (!dbUser) {
      res.status(401).send("Credenziali non valide");
    } else {
      _bcryptjs.compare(password, dbUser.password, (err: any, success: any) => {
        if (err) res.status(500).send("Bcrypt error " + err.message);
        else {
          if (!success) {
            res.status(401).send("Password non valida");
          } else {
            let token = creaToken(dbUser);
            res.setHeader("authorization", token);
            //Fa si che venga restituita al client
            res.setHeader("access-control-expose-headers", "authorization");
            res.send({ ris: "ok" });
          }
        }
      });
    }
  });
  rq.catch((err: any) => {
    res.status(500).send("errore esecuzione query " + err.message);
  });
  rq.finally(() => {
    client.close();
  });
});

function creaToken(data) {
  let currentDate = Math.floor(new Date().getTime() / 1000);
  let payload = {
    _id: data["_id"],
    username: data["username"],
    iat: data.iat || currentDate,
    exp: currentDate + parseInt(process.env.durataToken),
  };
  let token = _jwt.sign(payload, env.ENCRYPTION_KEY);

  return token;
}

app.use("/api/", (req: any, res: any, next: any) => {
  if (!req["body"]["skipCheckToken"]) {
    if (!req.headers["authorization"]) {
      res.status(403).send("Token mancante");
    } else {
      let token = req.headers["authorization"];
      _jwt.verify(token, env.ENCRYPTION_KEY, (err, payload) => {
        console.log(err + "err\n" + payload + "payload");
        if (err) {
          res.status(403).send("Token corrotto " + err);
        } else {
          let newToken = creaToken(payload);
          res.setHeader("authorization", newToken);
          res.setHeader("access-control-expose-headers", "authorization");
          req["payload"] = payload;
          next();
        }
      });
    }
  } else {
    next();
  }
});

//********************************************************************************************//
// Routes finali di risposta al client
//********************************************************************************************//

app.get("/api/perizie", async (req, res) => {
  const client = new MongoClient(connectionString);
  await client.connect();

  const db = client.db(DBNAME);
  const collection = db.collection("perizie");
  const docs = collection.find().toArray();
  docs
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});

app.get("/api/perizieById", async (req, res) => {
  const client = new MongoClient(connectionString);
  await client.connect();

  const cod_op = req.query.cod_op;

  const db = client.db(DBNAME);
  const collection = db.collection("perizie");
  const docs = collection.find({ codice_operatore: cod_op }).toArray();
  docs
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});

app.get("/api/utenti", async (req, res) => {
  const client = new MongoClient(connectionString);
  await client.connect();

  const db = client.db(DBNAME);
  const collection = db.collection("utenti");
  const docs = collection.find({}, { projection: { password: 0 } }).toArray();
  docs
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});

app.get("/api/utenteById", async (req, res) => {
  const client = new MongoClient(connectionString);
  await client.connect();

  console.log(req.query.id);
  const userCod = req.query.cod_op;

  const db = client.db(DBNAME);
  const collection = db.collection("utenti");

  const docs = collection.findOne(
    { codice: userCod },
    { projection: { password: 0 } }
  );
  docs
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});

app.get("/api/utenteByUsername", async (req, res) => {
  const client = new MongoClient(connectionString);
  await client.connect();

  console.log(req.query.id);
  const username = req.query.username;

  const db = client.db(DBNAME);
  const collection = db.collection("utenti");

  const docs = collection.findOne(
    { username: username },
    { projection: { password: 0 } }
  );
  docs
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});

app.post("/api/newUser", async (req, res) => {
  const client = new MongoClient(connectionString);
  await client.connect();

  let newUser = req["body"];
  const db = client.db(DBNAME);
  const collection = db.collection("utenti");
  const docs = collection.insertOne(newUser);
  docs
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});

app.delete("/api/deleteUser", async (req, res) => {
  const client = new MongoClient(connectionString);

  await client.connect();

  const db = client.db(DBNAME);
  const collection = db.collection("utenti");

  // Otteniamo l'ID dell'utente dal corpo della richiesta
  const userId = req.body.userId;

  // Eliminia mo l'utente con l'ID specificato
  const result = collection.deleteOne({ _id: new ObjectId(userId) });
  result
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});

app.post("/api/updateData", async (req, res) => {
  const client = new MongoClient(connectionString);

  await client.connect();

  const db = client.db(DBNAME);
  const collection = db.collection("perizie");

  // Get the photo URL and comment to update from the request body
  const pictureUrl = req.body.data["url"];
  const commentToUpdate = req.body.data["commento"];
  const periziaId = req.body.data["id"];

  // Query for documents where any element in the fotografie array has the specified URL
  const result = collection.updateOne(
    {
      _id: new ObjectId(periziaId),
      "fotografie.url": pictureUrl,
    },
    {
      $set: { "fotografie.$[elem].commento": commentToUpdate },
    },
    {
      arrayFilters: [{ "elem.url": pictureUrl }],
    }
  );
  result
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});

app.get("/api/fetchRoles", async (req, res) => {
  const client = new MongoClient(connectionString);

  try {
    await client.connect();

    const db = client.db(DBNAME);
    const collection = db.collection("utenti");

    // Execute the MongoDB query to fetch distinct values of "ruolo" field
    const distinctRoles = await collection.distinct("ruolo");

    // Send the distinct roles as response
    res.json(distinctRoles);
  } catch (err) {
    console.error("Error:", err);
    res.status(500).send("An error occurred while fetching roles.");
  } finally {
    client.close();
  }
});

app.post("/api/uploadPhotoesOnCloudinary", async (req, res) => {
  let imgBase64 = req.body.imgBase64;

  _cloudinary.v2.uploader
    .upload(imgBase64, { folder: "foto-perizie" })
    .catch((err) => {
      res.status(500).send(`Error while uploading file on Cloudinary: ${err}`);
    })
    .then(async function (response: UploadApiResponse) {
      const client = new MongoClient(connectionString);
      await client.connect();
      let collection = client.db(DBNAME).collection("utenti");
      let rq = collection.find().toArray();
      rq.then((data) => res.send({ url: response.secure_url }));
      rq.catch((err) =>
        res.status(500).send(`Errore esecuzione query: ${err}`)
      );
      rq.finally(() => client.close());
    });
});

app.post("/api/uploadPerizie", async (req, res) => {
  const client = new MongoClient(connectionString);
  await client.connect();

  const db = client.db(DBNAME);
  const collection = db.collection("perizie");

  // Get the perizia data from the request body
  const perizia = req.body.newPerizia;

  // Insert the perizia into the database
  const result = collection.insertOne(perizia);
  result
    .then((data) => {
      res.send(data);
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      client.close();
    });
});
//********************************************************************************************//
// Default route e gestione degli errori
//********************************************************************************************//

app.use("/", (req, res, next) => {
  res.status(404);
  if (req.originalUrl.startsWith("/api/")) {
    res.send(`Api non disponibile`);
  } else {
    res.send(paginaErrore);
  }
});

app.use("/", (err, req, res, next) => {
  console.log("************* SERVER ERROR ***************\n", err.stack);
  res.status(500).send(err.message);
});
