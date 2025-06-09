// ======= server.js =======
var express = require('express');
var mongoose = require('mongoose');
var path = require('path');
const { nanoid } = require('nanoid');
var session = require('express-session');
var bcrypt = require('bcrypt');
var User = require('./models/User');
var app = express();
var Url=require('./models/Url')

if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config(); // Only load from .env in dev
}

const apik = process.env.GOOGLE_API_KEY;
const db_pass=process.env.DB_PASSWORD

app.use(session({
  secret: 'mysecret',
  resave: false,
  saveUninitialized: false,
    cookie: {
    maxAge: 24 * 60 * 60 * 1000, // ✅ 1 day
    sameSite: true,              // ✅ helps prevent CSRF               // ❌ set to true if using HTTPS
  }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'public')); // point to where your templates are



mongoose.connect(`mongodb+srv://prathamshah485:${db_pass}@cluster0.ct3g8rx.mongodb.net/user?retryWrites=true&w=majority&appName=Cluster0`, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const axios = require('axios');

app.use(express.static('public',{index:'home.html'}));
app.use(express.urlencoded({ extended: true }));


async function isUrlSafe(url) {
  const apiKey = apik;
  const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const body = {
    client: {
      clientId: "url-checker-462415",
      clientVersion: "137.0.7151.69"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: url }]
    }
  }

  try {
    const response = await axios.post(apiUrl, body);
    return !response.data.matches; // true if no threats found
  } catch (error) {
    console.error('Error checking URL safety:', error);
    return false; // treat as unsafe on error
  }
}



app.get("/",async(req,res)=>{
    if(req.session.user){
      return res.render("home",{user:true})
    }
    else{
      return res.render("home",{user:false})
    }
})

// Signup route
app.post('/signup', async (req, res) => {
  console.log(req.body);
  var { email, password } = req.body;
  var hashed = await bcrypt.hash(password, 10);
  try {
    await User.create({ email, password: hashed });
    return res.redirect('login');
  } catch (e) {
    return res.send("Error: Email may already be used.");
  }
});

// Login route
app.post('/login', async (req, res) => {
  var { email, password } = req.body;
  var user = await User.findOne({ email });
  if (!user) return res.render("signup",{user:false});

  var match = await bcrypt.compare(password, user.password);
  if (!match) return res.send("Incorrect password");

  req.session.user = email;
  res.redirect('/dashboard');
});


app.get('/dashboard',async(req,res)=>{
  if(!req.session.user){
    return res.render('login',{user:false})
  }
  var obj= await Url.find({userEmail:req.session.user});
  var arr=[]
  console.log(obj)
  for(i of obj){
    arr.push({s: `${req.protocol}://${req.get('host')}/${i.shortId}`,l:i.originalUrl})
  }
  console.log(arr)
  return res.render('dashboard', { arr :arr, activePage: 'dashboard',user:true });

})

app.post('/shorten', async (req, res) => {
  const { originalUrl } = req.body;
  const shortId = nanoid(7);
  var mail=req.session.user
  await Url.create({ shortId : shortId , originalUrl : originalUrl , userEmail : mail});
  res.redirect('/dashboard')
});

app.post('/delete/:id',async(req,res)=>{
    var id=req.params.id
    await Url.deleteOne({shortId : id})
     var obj= await Url.find({userEmail:req.session.user});
  var arr=[]
  console.log(obj)
  for(i of obj){
   arr.push({s: `${req.protocol}://${req.get('host')}/${i.shortId}`,l:i.originalUrl})
  }
  console.log(arr)
  return res.render('dashboard', { arr :arr, activePage: 'dashboard' ,user:true});
})

app.get('/login', (req, res) => {
  // If user already logged in, redirect to dashboard
  if (req.session && req.session.user) {
    return res.render('login', { user: true });
  }
  return res.render('login', { user: false });
});

app.get('/signup', (req, res) => {
  if (req.session && req.session.user) {
    return res.render('signup', { user: true });
  }
  return res.render('signup', { user: false });
});


// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.render('login',{user:false});
  });
});

app.get('/:shortId', async (req, res) => {
  console.log("I reach here")
  const shortId = req.params.shortId;
  try {
    const url = await Url.findOne({ shortId });
    if (url) {
      res.redirect(url.originalUrl);
    } else {
      res.status(404).send('Short URL not found');
    }
  } catch (err) {
    res.status(500).send('Server Error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));