import 'dotenv/config';
import express from 'express';
import http from 'node:http';
import cors from 'cors';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { rateLimit } from 'express-rate-limit';
import { Server as SocketServer } from 'socket.io';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

const prisma = new PrismaClient();
const app = express();
app.set('trust proxy', 1); // Render runs behind one trusted reverse proxy
const server = http.createServer(app);
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be configured and contain at least 32 characters.');
}

const allowedOrigins = [...new Set([
  ...(process.env.CORS_ORIGINS || '').split(',').map(x => x.trim()).filter(Boolean),
  'https://stap-driver-api.onrender.com'
])];
const io = new SocketServer(server, {
  cors: { origin: allowedOrigins.length ? allowedOrigins : false, methods: ['GET', 'POST'] }
});
function emitOrderStatusChange(order,status,message){
  if(!order)return;
  const payload={id:order.id,orderCode:order.orderCode,status,message,changedAt:new Date().toISOString()};
  const recipients=[order.customerId,order.driverId].filter(Boolean);
  for(const userId of new Set(recipients))io.to('user:'+userId).emit('order:status-changed',payload);
}


app.use((req, res, next) => {
  // STAP apps are Android WebViews: always fetch the latest HTML, JS and CSS from Render.
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', "'wasm-unsafe-eval'"], workerSrc: ["'self'", 'blob:'], connectSrc: ["'self'", 'https://cdn.jsdelivr.net', 'https://tessdata.projectnaptha.com'], imgSrc: ["'self'", 'data:', 'blob:', 'https://images.unsplash.com'], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'] } } }));
app.use(express.static('public'));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin is not allowed by CORS'));
  }
}));
app.use(express.json({ limit: '24mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false }));
app.use('/api/drivers/documents', rateLimit({ windowMs: 60 * 60 * 1000, limit: 5, standardHeaders: 'draft-8', legacyHeaders: false }));

const DOCUMENT_KEY = createHash('sha256').update(JWT_SECRET).digest();
function encryptPrivate(value){if(value==null)return null;const nonce=randomBytes(12),cipher=createCipheriv('aes-256-gcm',DOCUMENT_KEY,nonce),encrypted=Buffer.concat([cipher.update(Buffer.isBuffer(value)?value:Buffer.from(String(value),'utf8')),cipher.final()]);return Buffer.concat([Buffer.from('STAP1'),nonce,cipher.getAuthTag(),encrypted])}
function decryptPrivate(value){if(!value)return null;const data=Buffer.from(value);if(data.subarray(0,5).toString()!=='STAP1')return data;const nonce=data.subarray(5,17),tag=data.subarray(17,33),body=data.subarray(33),decipher=createDecipheriv('aes-256-gcm',DOCUMENT_KEY,nonce);decipher.setAuthTag(tag);return Buffer.concat([decipher.update(body),decipher.final()])}
const DRIVER_PERIODIC_VERIFICATION_MS = 72 * 60 * 60 * 1000;
function periodicVerificationState(user, now = new Date()) {
  const dueAt = user?.periodicVehicleVerificationDueAt || (user?.driverVerifiedAt ? new Date(new Date(user.driverVerifiedAt).getTime() + DRIVER_PERIODIC_VERIFICATION_MS) : null);
  return { required:Boolean(user?.isVerified && dueAt && now.getTime() >= new Date(dueAt).getTime()), dueAt, status:user?.periodicVehicleVerificationStatus||'NOT_DUE' };
}
async function emitOrderToEligibleDrivers(drivers,event) {
  const ids=(drivers||[]).map(driver=>driver.id).filter(Boolean);
  if(!ids.length)return;
  const current=await prisma.user.findMany({where:{id:{in:ids},role:'DRIVER',isVerified:true,isBlocked:false}});
  for(const driver of current)if(!periodicVerificationState(driver).required)io.to('user:'+driver.id).emit('order:new',event);
}
async function emitNetworkOrderToEligibleDrivers(event) {
  const drivers = await prisma.user.findMany({where:{role:'DRIVER',isVerified:true,isBlocked:false},select:{id:true,isVerified:true,driverVerifiedAt:true,periodicVehicleVerificationDueAt:true,periodicVehicleVerificationStatus:true}});
  for (const driver of drivers) if (!periodicVerificationState(driver).required) io.to('user:'+driver.id).emit('order:new',event);
}
const publicUser = user => ({
  id: user.id, name: user.name, email: user.email, phone: user.phone,
  role: user.role, isBlocked: user.isBlocked, isVerified: user.isVerified, driverServiceCapabilities: user.driverServiceCapabilities || [],
  balanceAmd: user.balanceAmd, driverNegativeBalanceLimitAmd: user.driverNegativeBalanceLimitAmd ?? 0, rating: user.rating, driverLicense: user.driverLicense,
  driverFirstNameLatin: user.driverFirstNameLatin, driverLastNameLatin: user.driverLastNameLatin,
  driverPatronymicLatin: user.driverPatronymicLatin, driverLicenseSeries: user.driverLicenseSeries,
  driverLicenseExpiresAt: user.driverLicenseExpiresAt, driverLicenseIssuedAt: user.driverLicenseIssuedAt, driverLicenseCategories: user.driverLicenseCategories, driverTransmission: user.driverTransmission, vehicleMake:user.vehicleMake, vehicleModel:user.vehicleModel, vehicleYear:user.vehicleYear, vehiclePlate:user.vehiclePlate, vehicleColor:user.vehicleColor, vehicleDocumentsStatus:user.vehicleDocumentsStatus, vehicleVerificationMessage:user.vehicleVerificationMessage, driverDeliveryEnabled:user.driverDeliveryEnabled, periodicVehicleVerificationStatus:user.periodicVehicleVerificationStatus||'NOT_DUE', periodicVehicleVerificationDueAt:periodicVerificationState(user).dueAt, periodicVehicleVerificationSubmittedAt:user.periodicVehicleVerificationSubmittedAt, periodicVehicleVerificationRequired:periodicVerificationState(user).required, driverDocumentsStatus: user.driverDocumentsStatus, driverVerifiedAt: user.driverVerifiedAt, driverVerificationMessage: user.driverVerificationMessage, driverExperienceMonths: user.driverExperienceMonths, dateOfBirth: user.dateOfBirth, createdAt: user.createdAt
});
const normalizePhone = value => { let digits=String(value||'').replace(/\D/g,''); if(digits.startsWith('00'))digits=digits.slice(2); if(digits.startsWith('374'))return '+374'+digits.slice(3); if(digits.startsWith('0')&&digits.length===9)return '+374'+digits.slice(1); return digits?'+'+digits:''; };
const guestEmailForPhone = phone => 'guest+' + createHash('sha256').update(normalizePhone(phone)).digest('hex').slice(0,32) + '@guest.stap.invalid';
const LICENSE_CATEGORIES = ['AM','A1','A','B1','B','C1','C','D1','D','BE','C1E','CE','D1E','DE'];
function extractLicenseCategories(raw) {
  const text = String(raw || '').toUpperCase().replace(/[|]/g, 'I');
  const lines = text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  const heading = lines.findIndex(line => /CATEGOR|CAT[ÉE]GOR|КАТЕГОР|ԿԱՐԳԵՐ|ԿԱՐԳԵՐԸ/.test(line));
  const source = heading >= 0 ? lines.slice(heading, heading + 18).join(' ') : text;
  const found = new Set();
  for (const line of source.split(/\s+/)) {
    const token = line.replace(/^[^A-Z0-9]+|[^A-Z0-9]+$/g, '');
    if (LICENSE_CATEGORIES.includes(token)) found.add(token);
  }
  return LICENSE_CATEGORIES.filter(category => found.has(category));
}

function mrzDate(value, kind) {
  if (!/^\d{6}$/.test(value)) return null;
  const yy=Number(value.slice(0,2)),month=Number(value.slice(2,4)),day=Number(value.slice(4,6));
  if(month<1||month>12||day<1||day>31)return null;
  const currentYY=new Date().getUTCFullYear()%100;
  let year=2000+yy;
  if(kind==='birth'){
    const candidate=new Date(Date.UTC(year,month-1,day));
    if(yy>currentYY||candidate>new Date())year=1900+yy;
  }
  const date=new Date(Date.UTC(year,month-1,day));
  return date.getUTCMonth()===month-1&&date.getUTCDate()===day?date:null;
}
function parseMrzIdentity(raw) {
  const lines=String(raw||'').toUpperCase().split(/\r?\n/).map(line=>line.replace(/[^A-Z0-9<]/g,'')).filter(line=>line.length>=28);
  for(let i=0;i<lines.length;i++){
    const first=lines[i];
    if(!/^[PIAC][<A-Z]/.test(first))continue;
    if(first.length>=40&&lines[i+1]?.length>=40){
      const second=lines[i+1],names=first.slice(5).split('<<');
      const surname=(names[0]||'').replace(/</g,' ').trim(),given=(names[1]||'').replace(/</g,' ').trim();
      return {surname,givenNames:given,firstName:given.split(' ')[0]||'',passportNumber:second.slice(0,9).replace(/</g,''),birthDate:mrzDate(second.slice(13,19),'birth'),expiryDate:mrzDate(second.slice(21,27),'expiry')};
    }
    if(first.length>=28&&lines[i+1]?.length>=28&&lines[i+2]?.length>=28){
      const second=lines[i+1],third=lines[i+2],names=third.split('<<');
      const surname=(names[0]||'').replace(/</g,' ').trim(),given=(names[1]||'').replace(/</g,' ').trim();
      return {surname,givenNames:given,firstName:given.split(' ')[0]||'',passportNumber:first.slice(5,14).replace(/</g,''),birthDate:mrzDate(second.slice(0,6),'birth'),expiryDate:mrzDate(second.slice(8,14),'expiry')};
    }
  }
  return null;
}
function transliterateArmenian(value) {
  const map={Ա:'A',Բ:'B',Գ:'G',Դ:'D',Ե:'E',Զ:'Z',Է:'E',Ը:'Y',Թ:'T',Ժ:'ZH',Ի:'I',Լ:'L',Խ:'KH',Ծ:'TS',Կ:'K',Հ:'H',Ձ:'DZ',Ղ:'GH',Ճ:'CH',Մ:'M',Յ:'Y',Ն:'N',Շ:'SH',Ո:'O',Չ:'CH',Պ:'P',Ջ:'J',Ռ:'R',Ս:'S',Վ:'V',Տ:'T',Ր:'R',Ց:'TS',Ւ:'V',Փ:'P',Ք:'K',Օ:'O',Ֆ:'F'};
  return Array.from(String(value||'').toUpperCase()).map(ch=>map[ch]||ch).join('');
}
function labelledDate(raw, labels) {
  const lines=String(raw||'').split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  const datePattern=/(\d{4}[./-]\d{2}[./-]\d{2}|\d{2}[./-]\d{2}[./-]\d{4})/;
  for(let i=0;i<lines.length;i++){
    if(!labels.some(label=>label.test(lines[i])))continue;
    const match=(lines[i]+' '+(lines[i+1]||'')).match(datePattern);
    if(match){const p=match[1].split(/[./-]/),y=p[0].length===4?+p[0]:+p[2],m=+p[1],d=p[0].length===4?+p[2]:+p[0],date=new Date(Date.UTC(y,m-1,d));if(date.getUTCFullYear()===y&&date.getUTCMonth()===m-1&&date.getUTCDate()===d)return date;}
  }
  return null;
}
const signToken = user => jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { expiresIn: '12h', issuer: 'stap-driver-api' });

async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Մուտք գործեք համակարգ' });
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'stap-driver-api' });
    const user = await prisma.user.findUnique({ where: { id: payload.sub } });
    if (!user || user.isBlocked) return res.status(403).json({ error: 'Հաշիվը հասանելի չէ' });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Մուտքի ժամկետն ավարտվել է կամ token-ը սխալ է' });
  }
}
const only = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role)) return res.status(403).json({ error: 'Գործողությունն արգելված է' });
  next();
};
const verifiedDriver = (req, res, next) => {
  if (req.user?.role !== 'DRIVER' || !req.user.isVerified) return res.status(403).json({ error: 'Վարորդի հաշիվը դեռ հաստատված չէ ադմինի կողմից' });
  next();
};
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get('/api/notifications',auth,asyncRoute(async(req,res)=>{const notifications=await prisma.notification.findMany({where:{userId:req.user.id},orderBy:{createdAt:'desc'},take:30});res.json({notifications})}));
app.patch('/api/notifications/:id/read',auth,asyncRoute(async(req,res)=>{await prisma.notification.updateMany({where:{id:req.params.id,userId:req.user.id},data:{readAt:new Date()}});res.json({success:true})}));
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'STAP DRIVER API' }));
app.get('/api/health/ready',asyncRoute(async(_req,res)=>{
 await prisma.$queryRaw`SELECT 1`;
 res.json({ok:true,service:'STAP DRIVER API',database:'connected'});
}));

app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const input = z.object({
    name: z.string().trim().min(2).max(100),
    email: z.email().transform(v => v.toLowerCase()),
    phone: z.string().trim().min(7).max(30),
    password: z.string().min(10).max(128),
    role: z.enum(['CUSTOMER', 'DRIVER']).default('CUSTOMER'),
    driverLicense: z.string().trim().max(100).optional(),
    driverFirstNameLatin: z.string().trim().max(80).optional(),
    driverLastNameLatin: z.string().trim().max(80).optional(),
    driverPatronymicLatin: z.string().trim().max(80).optional(),
    driverLicenseSeries: z.string().trim().max(40).optional(),
    driverLicenseExpiresAt: z.iso.date().optional(),
    driverLicenseIssuedAt: z.iso.date().optional(),
    driverServiceCapabilities:z.array(z.enum(['ACCESSIBILITY_ASSIST','WHEELCHAIR_ASSIST','ELDERLY_ASSIST','CHILD_ASSIST','LUGGAGE_ASSIST'])).max(5).optional().default([])
  }).parse(req.body);
  if (input.role === 'DRIVER' && !input.driverLicense) return res.status(400).json({ error: 'Վարորդական իրավունքի տվյալները պարտադիր են' });
  const exists = await prisma.user.findUnique({ where: { email: input.email } });
  if (exists) return res.status(409).json({ error: 'Այս էլ․ փոստն արդեն գրանցված է' });
  const passwordHash = await bcrypt.hash(input.password, 12);
  const normalizedPhone=normalizePhone(input.phone);
  const customers=await prisma.user.findMany({where:{role:'CUSTOMER'},select:{id:true,email:true,phone:true}});
  const phoneCustomer=customers.find(person=>normalizePhone(person.phone)===normalizedPhone);
  let user;
  if(phoneCustomer&&phoneCustomer.email.endsWith('@guest.stap.invalid')&&input.role==='CUSTOMER'){
    user=await prisma.user.update({where:{id:phoneCustomer.id},data:{
      name:input.name,email:input.email,phone:input.phone,passwordHash
    }});
  }else{
    if(phoneCustomer&&input.role==='CUSTOMER')return res.status(409).json({error:'Այս հեռախոսահամարն արդեն կապված է գրանցված հաճախորդի հաշվին։ Մուտք գործեք այդ հաշվով։'});
    user=await prisma.user.create({data:{
      name:input.name,email:input.email,phone:input.phone,passwordHash,role:input.role,
      driverLicense:input.driverLicense||null,driverFirstNameLatin:input.driverFirstNameLatin||null,
      driverLastNameLatin:input.driverLastNameLatin||null,driverPatronymicLatin:input.driverPatronymicLatin||null,
      driverLicenseSeries:input.driverLicenseSeries||null,
      driverLicenseExpiresAt:input.driverLicenseExpiresAt?new Date(input.driverLicenseExpiresAt+'T00:00:00.000Z'):null,
      driverLicenseIssuedAt:input.driverLicenseIssuedAt?new Date(input.driverLicenseIssuedAt+'T00:00:00.000Z'):null,
      driverServiceCapabilities:input.role==='DRIVER'?input.driverServiceCapabilities:[]
    }});
  }
  res.status(201).json({ token: signToken(user), user: publicUser(user) });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const input = z.object({ email: z.string().trim().min(3).max(254), password: z.string().min(1).max(128) }).parse(req.body);
  const identity = input.email.trim();
  let user = null;
  if (identity.includes('@')) {
    user = await prisma.user.findUnique({ where: { email: identity.toLowerCase() } });
  } else {
    const normalized = normalizePhone(identity);
    const candidates = await prisma.user.findMany({ where: { phone: { not: null } } });
    user = candidates.find(candidate => normalizePhone(candidate.phone) === normalized) || null;
  }
  if (!user || !(await bcrypt.compare(input.password, user.passwordHash))) return res.status(401).json({ error: 'Հեռախոսահամարը կամ էլ․ փոստը կամ գաղտնաբառը սխալ է' });
  if (user.isBlocked) return res.status(403).json({ error: 'Հաշիվն արգելափակված է' });
  res.json({ token: signToken(user), user: publicUser(user) });
}));

app.get('/api/site-content',asyncRoute(async(_req,res)=>{const r=await prisma.siteContent.findUnique({where:{id:'main'}});res.json({content:r?.content||{}})}));
app.put('/api/admin/site-content',auth,only('ADMIN'),asyncRoute(async(req,res)=>{const input=z.object({content:z.record(z.string(),z.string())}).parse(req.body);const existing=await prisma.siteContent.findUnique({where:{id:'main'}});const content={...(existing?.content&&typeof existing.content==='object'?existing.content:{}),...Object.fromEntries(Object.entries(input.content).map(([k,v])=>[k,v.slice(0,12000)]))};const r=await prisma.siteContent.upsert({where:{id:'main'},create:{id:'main',content},update:{content}});io.emit('site-content:updated',{updatedAt:r.updatedAt});res.json({success:true,content:r.content,updatedAt:r.updatedAt,message:'Կայքի բովանդակությունը պահպանվեց և հրապարակվեց։'})}));
app.get('/api/tariffs',asyncRoute(async(_req,res)=>{const row=await prisma.siteContent.findUnique({where:{id:'main'}});const content={...(row?.content&&typeof row.content==='object'?row.content:{})};const tariffs=Array.isArray(content.tariffs)?[...content.tariffs]:[];if(!tariffs.some(item=>item?.id==='premium-delivery')){tariffs.push({id:'premium-delivery',title:'ՊՐԵՄԻՈՒՄ ԱՌԱՔՈՒՄ',description:'ԱՌԱՔՈՒՄԸ ԱՄԲՈՂՋ ԵՐԵՎԱՆՈՒՄ՝ ՖԻՔՍՎԱԾ 5,000 ԴՐԱՄ',requirements:'ԱՌԱՔԱՆԻՆ ՊԵՏՔ Է ԼԻՆԻ ԲԱՑ, ՏԵՍԱՆԵԼԻ ԵՎ ՍՏՈՒԳԵԼԻ, ԹԱՓԱՆՑԻԿ, ՉԿՈՏՐՎՈՂ, ՉՓՉԱՑՈՂ։',extraInfo:'ԱՊԱՀՈՎ ԵՎ ՎՍՏԱՀԵԼԻ ԱՌԱՔՈՒՄ՝ ՖԻՔՍՎԱԾ ԳՈՐԾԸՆԿԵՐՆԵՐԻ ԿՈՂՄԻՑ։',dispatchMode:'NETWORK',requiredLicenseCategory:'',requiredCapability:'',priceAmd:5000,image:'',active:true});content.tariffs=tariffs;await prisma.siteContent.upsert({where:{id:'main'},create:{id:'main',content},update:{content}});}res.json({tariffs:tariffs.filter(item=>item&&item.active!==false)});}));
app.put('/api/admin/tariffs',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const input=z.object({tariffs:z.array(z.object({id:z.string().trim().min(1).max(80),title:z.string().trim().min(2).max(120),description:z.string().trim().max(2000),requirements:z.string().trim().max(2000).optional().default(''),extraInfo:z.string().trim().max(1500).optional().default(''),dispatchMode:z.enum(['NETWORK','CATEGORY','CAPABILITY']).optional().default('NETWORK'),requiredLicenseCategory:z.string().trim().max(5).optional().default(''),requiredCapability:z.union([z.enum(['ACCESSIBILITY_ASSIST','WHEELCHAIR_ASSIST','ELDERLY_ASSIST','CHILD_ASSIST','LUGGAGE_ASSIST']),z.literal('')]).optional().default(''),priceAmd:z.number().int().min(0).max(100000000),image:z.string().max(5_000_000).optional().default(''),active:z.boolean().default(true)}).refine(item=>item.dispatchMode!=='CATEGORY'||Boolean(item.requiredLicenseCategory),{message:'Ընտրեք պարտադիր վարորդական կարգը։'}).refine(item=>item.dispatchMode!=='CAPABILITY'||Boolean(item.requiredCapability),{message:'Ընտրեք վարորդի պարտադիր հմտությունը։'})).max(100)}).parse(req.body);
 const row=await prisma.siteContent.findUnique({where:{id:'main'}});
 const content={...(row?.content&&typeof row.content==='object'?row.content:{}),tariffs:input.tariffs};
 await prisma.siteContent.upsert({where:{id:'main'},create:{id:'main',content},update:{content}});
 io.emit('site-content:updated',{kind:'tariffs',updatedAt:new Date()});
 res.json({success:true,tariffs:input.tariffs,message:'Սակագների ցանկը պահպանվեց։'});
}));
app.get('/api/admin/wallet-settings',auth,only('ADMIN'),asyncRoute(async(_req,res)=>{const row=await prisma.siteContent.findUnique({where:{id:'main'}});const raw=row?.content?.minDriverBalanceAmd;const minimumBalanceAmd=Number.isInteger(Number(raw))&&Number(raw)>=0?Number(raw):0;res.json({minimumBalanceAmd});}));
app.put('/api/admin/wallet-settings',auth,only('ADMIN'),asyncRoute(async(req,res)=>{const {minimumBalanceAmd}=z.object({minimumBalanceAmd:z.number().int().min(0).max(100000000)}).parse(req.body);const row=await prisma.siteContent.findUnique({where:{id:'main'}});const content={...(row?.content&&typeof row.content==='object'?row.content:{}),minDriverBalanceAmd:String(minimumBalanceAmd)};await prisma.siteContent.upsert({where:{id:'main'},create:{id:'main',content},update:{content}});res.json({success:true,minimumBalanceAmd,message:'Վարորդի նվազագույն հաշվեկշռի սահմանաչափը պահպանվեց։'});}));

app.get('/api/me', auth, (req, res) => res.json({ user: { ...publicUser(req.user), dateOfBirth: req.user.dateOfBirth } }));

app.patch('/api/profile', auth, asyncRoute(async (req,res)=>{const input=z.object({name:z.string().trim().min(2).max(120).optional(),phone:z.string().trim().min(5).max(30).optional(),dateOfBirth:z.iso.date().or(z.literal('')).optional()}).parse(req.body);const data={...(input.name!==undefined?{name:input.name}:{}),...(input.phone!==undefined?{phone:input.phone}:{}),...(input.dateOfBirth!==undefined?{dateOfBirth:input.dateOfBirth?new Date(input.dateOfBirth+'T00:00:00.000Z'):null}:{})};if(!Object.keys(data).length)return res.status(400).json({error:'Փոփոխության տվյալներ չկան։'});const user=await prisma.user.update({where:{id:req.user.id},data});res.json({user:publicUser(user),message:'Անձնական տվյալները պահպանվեցին։'})}));

app.patch('/api/customer/profile', auth, only('CUSTOMER'), asyncRoute(async (req, res) => {
  const { driverLicenseIssuedAt, dateOfBirth } = z.object({ driverLicenseIssuedAt: z.iso.date().or(z.literal('')), dateOfBirth: z.iso.date().or(z.literal('')).optional() }).parse(req.body);
  const user = await prisma.user.update({ where: { id: req.user.id }, data: {
    driverLicenseIssuedAt: driverLicenseIssuedAt ? new Date(driverLicenseIssuedAt+'T00:00:00.000Z') : null,
    ...(dateOfBirth!==undefined?{dateOfBirth:dateOfBirth?new Date(dateOfBirth+'T00:00:00.000Z'):null}:{})
  }});
  res.json({ user: publicUser(user), message: 'Վարորդական ստաժի տվյալը պահպանվեց։' });
}));


const YEREVAN_DISTRICT_GIS_URL='https://gis.yerevan.am/server/rest/services/Hosted/Yerevan_Districts/FeatureServer/0/query?where=1%3D1&outFields=settlement_name%2Ccommunity_code&returnGeometry=true&outSR=4326&f=geojson';
const YEREVAN_NEIGHBORHOOD_GIS_URL='https://gis.yerevan.am/server/rest/services/Yerevan_Named_Areas_Live/FeatureServer/138/query?where=1%3D1&outFields=toponym_name&returnGeometry=true&outSR=4326&f=geojson';
let yerevanDistrictFeaturesCache=null, yerevanDistrictFeaturesFetchedAt=0, yerevanDistrictFeaturesLoadPromise=null;
let yerevanNeighborhoodFeaturesCache=null, yerevanNeighborhoodFeaturesFetchedAt=0;
const yerevanGeocodeCache=new Map();
let lastYerevanGeocodeAt=0;
let yerevanDistrictAdjacencyCache=null;
function districtRings(feature){
 const g=feature?.geometry;if(!g)return [];
 if(g.type==='Polygon')return g.coordinates||[];
 if(g.type==='MultiPolygon')return (g.coordinates||[]).flat();
 return [];
}
function sharedDistrictBoundary(a,b){
 const tolerance=0.00008,minShared=0.00008;
 const ringsA=districtRings(a),ringsB=districtRings(b);
 for(const ra of ringsA)for(let i=0;i<ra.length-1;i++){
  const p=ra[i],q=ra[i+1],dx=q[0]-p[0],dy=q[1]-p[1],len=Math.hypot(dx,dy);
  if(len<minShared)continue;
  for(const rb of ringsB)for(let j=0;j<rb.length-1;j++){
   const r=rb[j],t=rb[j+1],ex=t[0]-r[0],ey=t[1]-r[1],elen=Math.hypot(ex,ey);
   if(elen<minShared||Math.abs(dx*ey-dy*ex)/len>tolerance)continue;
   if(Math.abs(dx*(r[1]-p[1])-dy*(r[0]-p[0]))/len>tolerance)continue;
   const ux=dx/len,uy=dy/len,pr=(r[0]-p[0])*ux+(r[1]-p[1])*uy,pt=(t[0]-p[0])*ux+(t[1]-p[1])*uy;
   const overlap=Math.min(len,Math.max(pr,pt))-Math.max(0,Math.min(pr,pt));
   if(overlap>=minShared)return true;
  }
 }
 return false;
}
function getYerevanDistrictAdjacency(features){
 if(yerevanDistrictAdjacencyCache)return yerevanDistrictAdjacencyCache;
 const graph=new Map(features.map(f=>[districtNameFromFeature(f),[]]));
 for(let i=0;i<features.length;i++)for(let j=i+1;j<features.length;j++){
  const a=districtNameFromFeature(features[i]),b=districtNameFromFeature(features[j]);
  if(a&&b&&sharedDistrictBoundary(features[i],features[j])){graph.get(a).push(b);graph.get(b).push(a);}
 }
 yerevanDistrictAdjacencyCache=graph;return graph;
}
function getShortestDistrictSequence(start,end,features){
 if(start===end)return [start];
 const graph=getYerevanDistrictAdjacency(features),queue=[[start]],visited=new Set([start]);
 while(queue.length){
  const path=queue.shift(),last=path[path.length-1];
  for(const next of graph.get(last)||[]){
   if(visited.has(next))continue;
   const candidate=[...path,next];if(next===end)return candidate;
   visited.add(next);queue.push(candidate);
  }
 }
 throw new Error('Ընտրված վարչական շրջանների միջև քարտեզային հարևանությունը հնարավոր չեղավ հաստատել։ Սակագինը չի հաշվարկվել։');
}
function YEREVAN_FARE_BY_DISTRICTS(pickupDistrict,destinationDistrict,features){
 const routeDistricts=getShortestDistrictSequence(pickupDistrict,destinationDistrict,features);
 const intermediateDistricts=routeDistricts.slice(1,-1);
 const endpointDistrictSurchargeAmd=pickupDistrict===destinationDistrict?0:5000;
 const intermediateDistrictSurchargeAmd=intermediateDistricts.length*3000;
 return {baseFareAmd:7000+endpointDistrictSurchargeAmd+intermediateDistrictSurchargeAmd,routeDistricts,intermediateDistricts,districtCount:routeDistricts.length,endpointDistrictSurchargeAmd,intermediateDistrictSurchargeAmd};
}
async function calculateYerevanDistrictFare(pickupDistrict,destinationDistrict){
 const features=await getYerevanDistrictFeatures();
 const names=new Set(features.map(districtNameFromFeature));
 if(!names.has(pickupDistrict)||!names.has(destinationDistrict))throw new Error('Ընտրեք Երևանի քարտեզում առկա երկու վարչական շրջանները։');
 return {pickupDistrict,destinationDistrict,...YEREVAN_FARE_BY_DISTRICTS(pickupDistrict,destinationDistrict,features)};
}
async function fetchJsonWithTimeout(url,options={},timeoutMs=18000){
 const response=await fetch(url,{...options,signal:AbortSignal.timeout(timeoutMs)});
 if(!response.ok)throw new Error('Քարտեզային ծառայությունը չպատասխանեց։');
 const data=await response.json();
 if(data.error)throw new Error(data.error.message||'Քարտեզային տվյալների սխալ։');
 return data;
}
const YEREVAN_DISTRICT_NAMES=['Աջափնյակ','Ավան','Արաբկիր','Դավթաշեն','Էրեբունի','Կենտրոն','Մալաթիա-Սեբաստիա','Նոր Նորք','Նորք-Մարաշ','Նուբարաշեն','Շենգավիթ','Քանաքեռ-Զեյթուն'];
const YEREVAN_REFERENCE_MAP_URL='https://oksanaharutyunyan.wordpress.com/2019/10/15/%D5%A5%D6%80%D6%87%D5%A1%D5%B6%D5%AB-%D5%BE%D5%A1%D6%80%D5%B9%D5%A1%D5%AF%D5%A1%D5%B6-%D5%B7%D6%80%D5%BB%D5%A1%D5%B6%D5%B6%D5%A5%D6%80%D5%A8/';
function isCompleteYerevanDistrictMap(features){
 if(!Array.isArray(features)||features.length!==12)return false;
 const names=features.map(feature=>String(feature?.properties?.settlement_name||'').trim());
 return features.every(feature=>feature?.geometry)&&new Set(names).size===12&&YEREVAN_DISTRICT_NAMES.every(name=>names.includes(name));
}
async function getYerevanDistrictFeatures(){
 if(yerevanDistrictFeaturesCache)return yerevanDistrictFeaturesCache;
 if(yerevanDistrictFeaturesLoadPromise)return yerevanDistrictFeaturesLoadPromise;
 yerevanDistrictFeaturesLoadPromise=(async()=>{
  const saved=await prisma.siteContent.findUnique({where:{id:'yerevan-district-map'}});
  const savedFeatures=saved?.content?.features;
  if(isCompleteYerevanDistrictMap(savedFeatures)){
   yerevanDistrictFeaturesCache=savedFeatures;
   return yerevanDistrictFeaturesCache;
  }
  const data=await fetchJsonWithTimeout(YEREVAN_DISTRICT_GIS_URL);
  if(!isCompleteYerevanDistrictMap(data.features))throw new Error('Երևանի 12 վարչական շրջանների քարտեզային սահմանները հասանելի չեն կամ ամբողջական չեն։ Գինը չի հաշվարկվել։');
  const mapContent={source:'Yerevan City GIS',sourceUrl:YEREVAN_DISTRICT_GIS_URL,referenceMapUrl:YEREVAN_REFERENCE_MAP_URL,referenceMapTitle:'Երևանի վարչական շրջանները (2019-10-15)',importedAt:new Date().toISOString(),districtCount:12,districtNames:YEREVAN_DISTRICT_NAMES,features:data.features};
  await prisma.siteContent.upsert({where:{id:'yerevan-district-map'},create:{id:'yerevan-district-map',content:mapContent},update:{content:mapContent}});
  yerevanDistrictFeaturesCache=data.features;
  yerevanDistrictFeaturesFetchedAt=Date.now();
  return yerevanDistrictFeaturesCache;
 })();
 try{return await yerevanDistrictFeaturesLoadPromise;}
 finally{yerevanDistrictFeaturesLoadPromise=null;}
}
async function getYerevanNeighborhoodFeatures(){
 if(yerevanNeighborhoodFeaturesCache&&Date.now()-yerevanNeighborhoodFeaturesFetchedAt<6*60*60*1000)return yerevanNeighborhoodFeaturesCache;
 const saved=await prisma.siteContent.findUnique({where:{id:'yerevan-neighborhood-map'}});
 const savedFeatures=saved?.content?.features;
 if(Array.isArray(savedFeatures)&&savedFeatures.length>=10&&savedFeatures.every(feature=>feature?.geometry&&String(feature?.properties?.toponym_name||'').trim())){
  yerevanNeighborhoodFeaturesCache=savedFeatures;
  yerevanNeighborhoodFeaturesFetchedAt=Date.now();
  return yerevanNeighborhoodFeaturesCache;
 }
 const data=await fetchJsonWithTimeout(YEREVAN_NEIGHBORHOOD_GIS_URL,{},25000);
 const features=(data.features||[]).filter(feature=>feature.geometry&&String(feature.properties?.toponym_name||'').trim());
 if(features.length<10)throw new Error('Երևանի թաղամասերի պաշտոնական GIS սահմանները ամբողջական չեն։ Գինը չի հաշվարկվել։');
 const mapContent={source:'Yerevan City GIS',sourceUrl:YEREVAN_NEIGHBORHOOD_GIS_URL,importedAt:new Date().toISOString(),neighborhoodFeatureCount:features.length,features};
 await prisma.siteContent.upsert({where:{id:'yerevan-neighborhood-map'},create:{id:'yerevan-neighborhood-map',content:mapContent},update:{content:mapContent}});
 yerevanNeighborhoodFeaturesCache=features;
 yerevanNeighborhoodFeaturesFetchedAt=Date.now();
 return features;
}
function neighborhoodNameFromFeature(feature){return String(feature.properties?.toponym_name||'').trim().replace(/\\s+/g,' ')}
function neighborhoodSequenceForRoute(coords,features){
 const sequence=[];let total=0,covered=0,ambiguous=0;
 const pushPoint=(lon,lat)=>{
  total++;
  const matches=features.filter(feature=>pointInDistrictGeometry(lon,lat,feature.geometry)&&neighborhoodNameFromFeature(feature));
  if(matches.length!==1){if(matches.length>1)ambiguous++;return}
  covered++;
  const name=neighborhoodNameFromFeature(matches[0]);
  if(name&&sequence[sequence.length-1]!==name)sequence.push(name);
 };
 for(let i=0;i<coords.length-1;i++){
  const a=coords[i],b=coords[i+1],distance=haversineMeters(a,b),steps=Math.max(1,Math.ceil(distance/25));
  for(let step=0;step<steps;step++){const t=step/steps;pushPoint(a[0]+(b[0]-a[0])*t,a[1]+(b[1]-a[1])*t)}
 }
 const last=coords[coords.length-1];if(last)pushPoint(last[0],last[1]);
 const coverage=total?covered/total:0,ambiguity=total?ambiguous/total:0;
 if(coverage<0.95||ambiguity>0.03||!sequence.length)throw new Error('Երթուղու թաղամասային սահմանները քարտեզում բավարար ճշտությամբ չեն համընկնում։ Գինը չի հաշվարկվել՝ սխալ սակագնից խուսափելու համար։');
 return {sequence:sequence.filter((name,index)=>index===0||name!==sequence[index-1]),coverage,ambiguity};
}
async function geocodeYerevanAddress(rawAddress){
 const address=String(rawAddress||'').trim();
 if(address.length<3)throw new Error('Մուտքագրեք ամբողջական հասցեն։');
 const cacheKey=address.toLocaleLowerCase('hy-AM');
 if(yerevanGeocodeCache.has(cacheKey))return yerevanGeocodeCache.get(cacheKey);
 const searches=[
  {query:address+', Երևան, Հայաստան',bounded:'1',language:'hy,en'},
  {query:address+', Yerevan, Armenia',bounded:'0',language:'en,hy'},
  {query:address+', Հայաստան',bounded:'0',language:'hy,en'}
 ];
 let results=[];
 for(const search of searches){
  const wait=Math.max(0,1100-(Date.now()-lastYerevanGeocodeAt));
  if(wait)await new Promise(resolve=>setTimeout(resolve,wait));
  lastYerevanGeocodeAt=Date.now();
  const url=new URL('https://nominatim.openstreetmap.org/search');
  url.searchParams.set('q',search.query);
  url.searchParams.set('format','jsonv2');url.searchParams.set('limit','1');url.searchParams.set('addressdetails','1');url.searchParams.set('countrycodes','am');
  url.searchParams.set('viewbox','44.30,40.35,44.75,40.00');url.searchParams.set('bounded',search.bounded);url.searchParams.set('accept-language',search.language);
  results=await fetchJsonWithTimeout(url.toString(),{headers:{'User-Agent':'STAP-DRIVER/1.0','Accept-Language':search.language}});
  if(Array.isArray(results)&&results.length)break;
 }
 if(!Array.isArray(results)||!results.length)throw new Error('Հասցեն քարտեզի վրա չգտնվեց։ Գրեք փողոցի անունը և շենքի համարը, օրինակ՝ «Աբովյան փողոց 12, Երևան», կամ նշեք մոտակա հայտնի օբյեկտը։');
 const addr=results[0].address||{};
 const point={lat:Number(results[0].lat),lon:Number(results[0].lon),displayName:results[0].display_name,neighborhood:addr.neighbourhood||addr.suburb||addr.quarter||addr.city_district||null};
 if(!Number.isFinite(point.lat)||!Number.isFinite(point.lon)||point.lat<40||point.lat>40.35||point.lon<44.3||point.lon>44.75)throw new Error('Նշված հասցեն Երևանի սահմաններից դուրս է։');
 yerevanGeocodeCache.set(cacheKey,point);
 if(yerevanGeocodeCache.size>1000)yerevanGeocodeCache.delete(yerevanGeocodeCache.keys().next().value);
 return point;
}
function pointInRing(lon,lat,ring){
 let inside=false;
 for(let i=0,j=ring.length-1;i<ring.length;j=i++){
  const xi=ring[i][0],yi=ring[i][1],xj=ring[j][0],yj=ring[j][1];
  const intersects=((yi>lat)!==(yj>lat))&&(lon<(xj-xi)*(lat-yi)/(yj-yi+Number.EPSILON)+xi);
  if(intersects)inside=!inside;
 }
 return inside;
}
function pointInDistrictGeometry(lon,lat,geometry){
 if(!geometry)return false;
 const polygons=geometry.type==='Polygon'?[geometry.coordinates]:geometry.type==='MultiPolygon'?geometry.coordinates:[];
 return polygons.some(poly=>Array.isArray(poly[0])&&pointInRing(lon,lat,poly[0])&&!poly.slice(1).some(hole=>pointInRing(lon,lat,hole)));
}
function districtNameFromFeature(feature){
 const raw=String(feature.properties?.settlement_name||'').trim();
 const aliases={'Աջափնյակ':'Աջափնյակ','Ավան':'Ավան','Արաբկիր':'Արաբկիր','Դավթաշեն':'Դավթաշեն','Էրեբունի':'Էրեբունի','Կենտրոն':'Կենտրոն','Մալաթիա-Սեբաստիա':'Մալաթիա-Սեբաստիա','Նոր Նորք':'Նոր Նորք','Նորք-Մարաշ':'Նորք-Մարաշ','Նուբարաշեն':'Նուբարաշեն','Շենգավիթ':'Շենգավիթ','Քանաքեռ-Զեյթուն':'Քանաքեռ-Զեյթուն'};
 return aliases[raw]||raw;
}
function haversineMeters(a,b){
 const rad=v=>v*Math.PI/180,R=6371000,dLat=rad(b[1]-a[1]),dLon=rad(b[0]-a[0]);
 const x=Math.sin(dLat/2)**2+Math.cos(rad(a[1]))*Math.cos(rad(b[1]))*Math.sin(dLon/2)**2;
 return 2*R*Math.asin(Math.sqrt(x));
}
function districtSequenceForRoute(coords,features){
 const sequence=[];let total=0,covered=0,ambiguous=0;
 const pushPoint=(lon,lat)=>{
  total++;
  const matches=features.filter(feature=>pointInDistrictGeometry(lon,lat,feature.geometry));
  if(matches.length!==1){if(matches.length>1)ambiguous++;return}
  covered++;
  const name=districtNameFromFeature(matches[0]);
  if(name&&sequence[sequence.length-1]!==name)sequence.push(name);
 };
 for(let i=0;i<coords.length-1;i++){
  const a=coords[i],b=coords[i+1],distance=haversineMeters(a,b),steps=Math.max(1,Math.ceil(distance/25));
  for(let step=0;step<steps;step++){
   const t=step/steps;pushPoint(a[0]+(b[0]-a[0])*t,a[1]+(b[1]-a[1])*t);
  }
 }
 const last=coords[coords.length-1];if(last)pushPoint(last[0],last[1]);
 if(!total||covered/total<0.95||ambiguous/total>0.03||!sequence.length)throw new Error('Երթուղին ամբողջությամբ չի համընկնում Երևանի 12 վարչական շրջանների քարտեզային սահմաններին։ Գինը չի հաշվարկվել։');
 return sequence.filter((name,index)=>index===0||name!==sequence[index-1]);
}
function districtForPoint(point,features){
 const matches=features.filter(feature=>pointInDistrictGeometry(point.lon,point.lat,feature.geometry));
 if(matches.length!==1)throw new Error('Հասցեի վարչական շրջանը քարտեզով միանշանակ որոշել չհաջողվեց։ Ստուգեք փողոցի անունն ու շենքի համարը։');
 const name=districtNameFromFeature(matches[0]);
 if(!name)throw new Error('Հասցեի վարչական շրջանի անունը քարտեզում բացակայում է։');
 return name;
}
async function getUrgentDemandCoefficient(isUrgent){
 if(!isUrgent)return {pendingUrgentOrders:0,demandCoefficientPercent:0};
 const pendingUrgentOrders=await prisma.order.count({where:{isUrgent:true,status:'OPEN',scheduleType:'NOW',scheduledAt:null,isTest:false}});
 const totalIncludingCurrent=pendingUrgentOrders+1;
 return {pendingUrgentOrders,totalIncludingCurrent,demandCoefficientPercent:totalIncludingCurrent>=3?5:totalIncludingCurrent>=2?2.5:0};
}
function calculateUrgentDemandCharge(baseFareAmd,extraChargeAmd,isUrgent,percent){
 return isUrgent&&percent?Math.round((baseFareAmd+extraChargeAmd+2500)*percent/100):0;
}
async function calculateYerevanRoute(pickupAddress,destinationAddress){
 const [pickup,destination,districtFeatures]=await Promise.all([geocodeYerevanAddress(pickupAddress),geocodeYerevanAddress(destinationAddress),getYerevanDistrictFeatures()]);
 const pickupDistrict=districtForPoint(pickup,districtFeatures),destinationDistrict=districtForPoint(destination,districtFeatures);
 const routeUrl='https://router.project-osrm.org/route/v1/driving/'+pickup.lon+','+pickup.lat+';'+destination.lon+','+destination.lat+'?overview=full&geometries=geojson&steps=false';
 const routeData=await fetchJsonWithTimeout(routeUrl),route=routeData.routes?.[0],coords=route?.geometry?.coordinates;
 if(!route||!Array.isArray(coords)||coords.length<2)throw new Error('Այս հասցեների միջև մեքենայի երթուղի չհաջողվեց կառուցել։');
 const routeDistricts=districtSequenceForRoute(coords,districtFeatures);
 if(routeDistricts[0]!==pickupDistrict||routeDistricts[routeDistricts.length-1]!==destinationDistrict)throw new Error('Երթուղու սկզբնական կամ վերջնական վարչական շրջանը չի համընկնում հասցեների քարտեզային դիրքի հետ։ Հասցեները ճշտեք։');
 const neighborhoodFeatures=await getYerevanNeighborhoodFeatures();
 const neighborhoodResult=neighborhoodSequenceForRoute(coords,neighborhoodFeatures);
 const routeNeighborhoods=neighborhoodResult.sequence;
 const districtCount=new Set(routeDistricts).size;
 const fareBreakdown=YEREVAN_FARE_BY_ROUTE(routeDistricts,pickupDistrict,destinationDistrict);
 return {pickup,destination,pickupDistrict,destinationDistrict,routeDistricts,routeNeighborhoods,neighborhoodCoverage:neighborhoodResult.coverage,neighborhoodAmbiguity:neighborhoodResult.ambiguity,districtCount,...fareBreakdown,distanceMeters:Math.round(route.distance),durationSeconds:Math.round(route.duration)};
}

app.get('/api/geo/neighborhoods',auth,asyncRoute(async(req,res)=>{const features=await getYerevanNeighborhoodFeatures();const names=[...new Set(features.map(neighborhoodNameFromFeature).filter(Boolean))].sort((x,y)=>x.localeCompare(y,'hy'));res.json({neighborhoods:names});}));

app.get('/api/geo/streets',auth,asyncRoute(async(req,res)=>{
 const district=String(req.query.district||'').trim(),q=String(req.query.q||'').trim();
 const allowed=['Աջափնյակ','Ավան','Արաբկիր','Դավթաշեն','Էրեբունի','Քանաքեռ-Զեյթուն','Կենտրոն','Մալաթիա-Սեբաստիա','Նոր Նորք','Նորք-Մարաշ','Նուբարաշեն','Շենգավիթ'];
 if(!allowed.includes(district))return res.status(400).json({error:'Ընտրեք Երևանի վարչական շրջանը։'});
 if(q.length<2)return res.json({streets:[]});
 const features=await getYerevanDistrictFeatures();
 const url=new URL('https://nominatim.openstreetmap.org/search');
 url.searchParams.set('q',q+', '+district+', Երևան, Հայաստան');
 url.searchParams.set('format','jsonv2');url.searchParams.set('limit','15');url.searchParams.set('addressdetails','1');url.searchParams.set('countrycodes','am');
 url.searchParams.set('viewbox','44.30,40.35,44.75,40.00');url.searchParams.set('bounded','1');url.searchParams.set('accept-language','hy,en');
 const wait=Math.max(0,1100-(Date.now()-lastYerevanGeocodeAt));if(wait)await new Promise(resolve=>setTimeout(resolve,wait));lastYerevanGeocodeAt=Date.now();
 const results=await fetchJsonWithTimeout(url.toString(),{headers:{'User-Agent':'STAP-DRIVER/1.0','Accept-Language':'hy,en'}});
 const streets=[...new Set((Array.isArray(results)?results:[]).filter(item=>{
  const lat=Number(item.lat),lon=Number(item.lon);
  if(!Number.isFinite(lat)||!Number.isFinite(lon))return false;try{return districtForPoint({lat,lon},features)===district}catch(_){return false}
 }).map(item=>item.address?.road||item.address?.pedestrian||item.address?.residential||item.name).filter(Boolean))].slice(0,8);
 res.json({streets});
}));

app.post('/api/routes/quote',asyncRoute(async(req,res)=>{
 const input=z.object({pickupDistrict:z.string().trim().min(2).max(80),destinationDistrict:z.string().trim().min(2).max(80),isUrgent:z.boolean().default(false),extraChargeAmd:z.number().int().min(0).max(1000000).default(0)}).parse(req.body);
 try {
  const fare=await calculateYerevanDistrictFare(input.pickupDistrict,input.destinationDistrict);
  const demand=await getUrgentDemandCoefficient(input.isUrgent);
  const demandExtraChargeAmd=calculateUrgentDemandCharge(fare.baseFareAmd,input.extraChargeAmd,input.isUrgent,demand.demandCoefficientPercent);
  const urgentExtraChargeAmd=input.isUrgent?2500+demandExtraChargeAmd:0;
  const quotedFareAmd=fare.baseFareAmd+input.extraChargeAmd+urgentExtraChargeAmd;
  res.json({...fare,demandCoefficientPercent:demand.demandCoefficientPercent,pendingUrgentOrders:demand.pendingUrgentOrders||0,demandExtraChargeAmd,urgentExtraChargeAmd,quotedFareAmd});
 } catch(error) {
  console.warn('District fare quote could not be calculated:',error.message);
  res.status(422).json({error:error.message||'Վարչական շրջանների սակագինը հնարավոր չեղավ հաշվարկել։'});
 }
}));

app.post('/api/orders', auth, only('CUSTOMER'), asyncRoute(async (req, res) => {
  const input = z.object({
    pickupDistrict:z.string().trim().min(2).max(80).optional(),destinationDistrict:z.string().trim().min(2).max(80).optional(),pickupAddress:z.string().trim().min(3).max(300).optional(),destinationAddress:z.string().trim().min(3).max(300).optional(),senderName:z.string().trim().max(120).optional(),senderPhone:z.string().trim().max(30).optional(),recipientPhone:z.string().trim().max(30).optional(),recipientName:z.string().trim().max(120).optional(),parcelAccepted:z.boolean().optional(),
    serviceId:z.string().trim().min(1).max(80).optional(),
    extraChargeAmd:z.number().int().min(0).max(1000000).default(0),isUrgent:z.boolean().default(false),
    requiredLicenseCategory:z.string().trim().min(1).max(5).default('B'),transmissionType:z.enum(['AUTOMATIC','MANUAL']).default('AUTOMATIC'),vehicleFuelType:z.enum(['PETROL','ELECTRIC','HYBRID']).default('PETROL'),passengerCount:z.number().int().min(1).max(5).default(1),
    note:z.string().max(1000).optional(),pickupNote:z.string().trim().max(500).optional().or(z.literal('')),destinationNote:z.string().trim().max(500).optional().or(z.literal('')),isTest:z.boolean().default(false)
  }).parse(req.body);
  const contentRow=await prisma.siteContent.findUnique({where:{id:'main'}});
  const catalogue=Array.isArray(contentRow?.content?.tariffs)?contentRow.content.tariffs:[];
  const service=input.serviceId?catalogue.find(item=>item?.id===input.serviceId&&item.active!==false):null;
  if(input.serviceId&&!service)return res.status(400).json({error:'Ընտրված ծառայությունն այլևս հասանելի չէ։ Թարմացրեք էջը։'});
  const isPremiumDelivery=service?.id==='premium-delivery';
  if(isPremiumDelivery){if(!input.senderName?.trim()||!input.recipientName?.trim())return res.status(400).json({error:'Լրացրեք ուղարկողի և ստացողի անունները։'});if(!input.parcelAccepted)return res.status(400).json({error:'Հաստատեք առաքանու ընդունելի պայմանները։'});for(const [label,value] of [['ուղարկողի',input.senderPhone],['ստացողի',input.recipientPhone]])if(!value||normalizePhone(value).replace(/\\D/g,'').length<7)return res.status(400).json({error:'Մուտքագրեք '+label+' ճիշտ հեռախոսահամարը։'});if(!input.pickupAddress||!input.destinationAddress)return res.status(400).json({error:'Լրացրեք ուղարկողի և ստացողի ամբողջական հասցեները։'});}
  const route=isPremiumDelivery?{baseFareAmd:0,pickupDistrict:'Առաքում',destinationDistrict:'Երևան',routeDistricts:[],districtCount:0,intermediateDistricts:[]}:await calculateYerevanDistrictFare(input.pickupDistrict,input.destinationDistrict);
  const servicePriceAmd=Number.isInteger(service?.priceAmd)?service.priceAmd:0;
  const dispatchMode=['CATEGORY','CAPABILITY'].includes(service?.dispatchMode)?service.dispatchMode:'NETWORK';
  const requiredLicenseCategory=dispatchMode==='CATEGORY'?(service?.requiredLicenseCategory||'B'):input.requiredLicenseCategory;
  const requiredCapability=dispatchMode==='CAPABILITY'?(service?.requiredCapability||''):'';
  let eligibleDrivers=[];
  if(dispatchMode==='CATEGORY'||dispatchMode==='CAPABILITY'){
   eligibleDrivers=await prisma.user.findMany({where:{role:'DRIVER',isVerified:true,isBlocked:false,...(dispatchMode==='CATEGORY'?{driverLicenseCategories:{has:requiredLicenseCategory}}:{driverServiceCapabilities:{has:requiredCapability}}),...(input.transmissionType==='MANUAL'?{driverTransmission:'MANUAL'}:{})},select:{id:true}});
   if(!eligibleDrivers.length)return res.status(409).json({error:dispatchMode==='CAPABILITY'?'Այս հատուկ հմտությունն ունեցող հաստատված վարորդ այս պահին չկա։ Վարորդները պետք է իրենց պրոֆիլում նշեն այդ հմտությունը։':'Այս վարորդական կարգով հաստատված վարորդ այս պահին չկա։ Ընտրեք այլ ծառայություն կամ կապվեք ադմինի հետ։'});
  }
  const totalExtraAmd=input.extraChargeAmd+servicePriceAmd;
  const pickupAddress=isPremiumDelivery?input.pickupAddress.trim():route.pickupDistrict+' վարչական շրջան',destinationAddress=isPremiumDelivery?input.destinationAddress.trim():route.destinationDistrict+' վարչական շրջան';
  const orderNote=isPremiumDelivery?['ՊՐԵՄԻՈՒՄ ԱՌԱՔՈՒՄ','Ուղարկող՝ '+input.senderName,'Ուղարկողի հեռախոս՝ '+input.senderPhone,'Ստացող՝ '+input.recipientName,'Ստացողի հեռախոս՝ '+input.recipientPhone,'Առաքանու սահմանափակում՝ առավելագույնը 10 կգ, բաց, տեսանելի, ստուգելի, թափանցիկ, չկոտրվող և չփչացող'].join(' | ').slice(0,1000):input.note;
  const demand=await getUrgentDemandCoefficient(input.isUrgent);
  const demandExtraChargeAmd=isPremiumDelivery?0:calculateUrgentDemandCharge(route.baseFareAmd,totalExtraAmd,input.isUrgent,demand.demandCoefficientPercent);
  const urgentExtraChargeAmd=input.isUrgent?2500+demandExtraChargeAmd:0;
  const fareAmd=(isPremiumDelivery?5000:route.baseFareAmd)+(isPremiumDelivery?0:input.extraChargeAmd)+(isPremiumDelivery?0:servicePriceAmd)+urgentExtraChargeAmd;
  const order=await prisma.order.create({data:{orderCode:await generateUniqueOrderCode(),customerId:req.user.id,isUrgent:input.isUrgent,urgentExtraChargeAmd,demandCoefficientChargeAmd:demandExtraChargeAmd,dispatchMode,serviceId:service?.id||null,serviceCapability:requiredCapability||null,serviceTitle:service?.title||null,serviceRequirements:service?.requirements||service?.description||null,servicePriceAmd,pickupAddress,destinationAddress,routeDistricts:route.routeDistricts,routeNeighborhoods:[],routeDistanceMeters:null,fareAmd,requiredLicenseCategory,transmissionType:input.transmissionType,vehicleFuelType:input.vehicleFuelType,passengerCount:input.passengerCount,note:orderNote,pickupNote:input.pickupNote||null,destinationNote:input.destinationNote||null,isTest:input.isTest}});
  const event={id:order.id,orderCode:order.orderCode,isTest:order.isTest,pickupAddress:order.pickupAddress,destinationAddress:order.destinationAddress,fareAmd:order.fareAmd,serviceTitle:order.serviceTitle,createdAt:order.createdAt};
  if(dispatchMode==='CATEGORY')await emitOrderToEligibleDrivers(eligibleDrivers,event);else await emitNetworkOrderToEligibleDrivers(event);
  res.status(201).json({order,routeDistricts:route.routeDistricts,districtCount:route.districtCount,message:'Պատվերը հրապարակվեց՝ ընտրված ծառայության և համապատասխան վարորդների պայմաններով։'});
}));

app.post('/api/orders/guest',rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:'draft-8',legacyHeaders:false}),asyncRoute(async(req,res)=>{
 const input=z.object({
  name:z.string().trim().min(2).max(100),phone:z.string().trim().min(7).max(30),
  pickupDistrict:z.string().trim().min(2).max(80),destinationDistrict:z.string().trim().min(2).max(80),serviceId:z.string().trim().min(1).max(80).optional(),
  extraChargeAmd:z.number().int().min(0).max(1000000).default(0),isUrgent:z.boolean().default(false),
  requiredLicenseCategory:z.string().trim().min(1).max(5).default('B'),
  transmissionType:z.enum(['AUTOMATIC','MANUAL']).default('AUTOMATIC'),
  note:z.string().max(1000).optional(),pickupNote:z.string().trim().max(500).optional().or(z.literal('')),
  destinationNote:z.string().trim().max(500).optional().or(z.literal(''))
 }).parse(req.body);
 const phone=normalizePhone(input.phone);
 if(phone.replace(/\D/g,'').length<7)return res.status(400).json({error:'Մուտքագրեք ճիշտ հեռախոսահամար։'});
 const route=await calculateYerevanDistrictFare(input.pickupDistrict,input.destinationDistrict);
 const contentRow=await prisma.siteContent.findUnique({where:{id:'main'}});
 const catalogue=Array.isArray(contentRow?.content?.tariffs)?contentRow.content.tariffs:[];
 const service=input.serviceId?catalogue.find(item=>item?.id===input.serviceId&&item.active!==false):null;
 if(input.serviceId&&!service)return res.status(400).json({error:'Ընտրված ծառայությունն այլևս հասանելի չէ։ Թարմացրեք էջը։'});
 const servicePriceAmd=Number.isInteger(service?.priceAmd)?service.priceAmd:0;
 const dispatchMode=['CATEGORY','CAPABILITY'].includes(service?.dispatchMode)?service.dispatchMode:'NETWORK';
 const requiredLicenseCategory=dispatchMode==='CATEGORY'?(service?.requiredLicenseCategory||'B'):input.requiredLicenseCategory;
 const requiredCapability=dispatchMode==='CAPABILITY'?(service?.requiredCapability||''):'';
 let eligibleDrivers=[];
 if(dispatchMode!=='NETWORK'){
  eligibleDrivers=await prisma.user.findMany({where:{role:'DRIVER',isVerified:true,isBlocked:false,...(dispatchMode==='CATEGORY'?{driverLicenseCategories:{has:requiredLicenseCategory}}:{driverServiceCapabilities:{has:requiredCapability}})},select:{id:true}});
  if(!eligibleDrivers.length)return res.status(409).json({error:'Այս ծառայության պահանջներին համապատասխան հաստատված վարորդ այս պահին չկա։'});
 }
 
 const demand=await getUrgentDemandCoefficient(input.isUrgent);
 const demandExtraChargeAmd=calculateUrgentDemandCharge(route.baseFareAmd,servicePriceAmd+input.extraChargeAmd,input.isUrgent,demand.demandCoefficientPercent);
 const urgentExtraChargeAmd=input.isUrgent?2500+demandExtraChargeAmd:0;
 const fareAmd=route.baseFareAmd+servicePriceAmd+input.extraChargeAmd+urgentExtraChargeAmd;
 const customers=await prisma.user.findMany({where:{role:'CUSTOMER'},select:{id:true,email:true,phone:true}});
 let customer=customers.find(person=>normalizePhone(person.phone)===phone);
 if(customer&&!customer.email.endsWith('@guest.stap.invalid'))return res.status(409).json({error:'Այս հեռախոսահամարը գրանցված հաշիվ ունի։ Շարունակելու համար մուտք գործեք այդ հաշվով։'});
 if(!customer){
  const email=guestEmailForPhone(phone);
  customer=await prisma.user.findUnique({where:{email}});
  if(!customer)customer=await prisma.user.create({data:{name:input.name,email,phone:input.phone,passwordHash:await bcrypt.hash(randomBytes(32).toString('hex'),12),role:'CUSTOMER'}});
 }
 const order=await prisma.order.create({data:{
  orderCode:await generateUniqueOrderCode(),customerId:customer.id,isUrgent:input.isUrgent,urgentExtraChargeAmd,demandCoefficientChargeAmd:demandExtraChargeAmd,phonePrimary:input.phone,dispatchMode,serviceId:service?.id||null,serviceCapability:requiredCapability||null,serviceTitle:service?.title||null,serviceRequirements:service?.requirements||service?.description||null,servicePriceAmd,requiredLicenseCategory,
  pickupAddress:route.pickupDistrict+' վարչական շրջան',destinationAddress:route.destinationDistrict+' վարչական շրջան',
  routeDistricts:route.routeDistricts,routeNeighborhoods:[],fareAmd,requiredLicenseCategory:input.requiredLicenseCategory,
  transmissionType:input.transmissionType,note:input.note,pickupNote:input.pickupNote||null,destinationNote:input.destinationNote||null
 }});
 const guestEvent={id:order.id,isTest:false,pickupAddress:order.pickupAddress,destinationAddress:order.destinationAddress,fareAmd:order.fareAmd,isUrgent:order.isUrgent,serviceTitle:order.serviceTitle,createdAt:order.createdAt};
  if(dispatchMode!=='NETWORK')await emitOrderToEligibleDrivers(eligibleDrivers,guestEvent);else await emitNetworkOrderToEligibleDrivers(guestEvent);
 const admins=await prisma.user.findMany({where:{role:'ADMIN'},select:{id:true}});
 const title='Նոր պատվեր՝ առանց գրանցման',notificationMessage='Հաճախորդ՝ '+input.name+' · '+input.phone+' · '+order.pickupAddress+' → '+order.destinationAddress;
 if(admins.length){await prisma.notification.createMany({data:admins.map(admin=>({userId:admin.id,title,message:notificationMessage,type:'NEW_GUEST_ORDER'}))});for(const admin of admins)io.to('user:'+admin.id).emit('notification:new',{title,message:notificationMessage,type:'NEW_GUEST_ORDER',orderId:order.id,createdAt:new Date()});}
 res.status(201).json({success:true,order:{id:order.id,orderCode:order.orderCode,fareAmd:order.fareAmd},routeDistricts:route.routeDistricts,demandCoefficientPercent:demand.demandCoefficientPercent,message:'Պատվերն ուղարկվեց վարորդներին և ադմինին։ Հեռախոսահամարի պատվերներն ու գնահատականները պահվում են մեկ հաճախորդային պատմության մեջ։'});
}));

app.get('/api/admin/orders', auth, only('ADMIN'), asyncRoute(async (req,res)=>{
  const orders=await prisma.order.findMany({where:{isTest:true},orderBy:{createdAt:'desc'},include:{
    customer:{select:{id:true,name:true,phone:true,rating:true}},
    driver:{select:{id:true,name:true,phone:true,isVerified:true}}
  }});
  res.json({orders:await withCustomerOrderNumbers(orders.map(order=>({...order,vehicleInspectionReport:order.vehicleInspectionReport?{hasReport:true,hasDamage:Boolean(order.vehicleInspectionReport.hasDamage),recordedAt:order.vehicleInspectionReport.recordedAt}:null,vehicleReturnInspection:undefined})))});
}));

app.get('/api/admin/customers',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const users=await prisma.user.findMany({where:{role:'CUSTOMER'},orderBy:{createdAt:'desc'},select:{id:true,name:true,email:true,phone:true,rating:true,isBlocked:true,createdAt:true}});
 const orders=await ensureOrderCodes(await prisma.order.findMany({orderBy:{createdAt:'desc'},include:{customer:{select:{id:true,name:true,email:true,phone:true,rating:true}},driver:{select:{id:true,name:true,phone:true,rating:true}},ratings:{orderBy:{createdAt:'desc'},include:{fromUser:{select:{id:true,name:true,phone:true,role:true}},toUser:{select:{id:true,name:true,phone:true,role:true}}}}}}));
 const groups=new Map(),accountGroups=new Map(),keyFor=value=>normalizePhone(value)||null;
 for(const user of users){const key=keyFor(user.phone)||('account:'+user.id);let group=groups.get(key);if(!group){group={id:user.id,name:user.name,email:user.email,phone:user.phone,rating:user.rating,isBlocked:user.isBlocked,createdAt:user.createdAt,orders:[],accounts:[]};groups.set(key,group)}else if(group.email?.endsWith('@guest.stap.invalid')&&!user.email?.endsWith('@guest.stap.invalid'))Object.assign(group,{id:user.id,name:user.name,email:user.email,phone:user.phone,rating:user.rating,isBlocked:user.isBlocked,createdAt:user.createdAt});group.accounts.push(user.id);accountGroups.set(user.id,group)}
 for(const order of orders){const customer=order.customer,customerPhone=keyFor(customer?.phone),orderPhone=keyFor(order.phonePrimary);let group=(customer&&accountGroups.get(customer.id))||groups.get(customerPhone)||groups.get(orderPhone);if(!group){const key=customerPhone||orderPhone||('order:'+order.id);group={id:customer?.id||order.id,name:customer?.name||'Անանուն պատվիրատու',email:customer?.email||'',phone:customer?.phone||order.phonePrimary||'',rating:customer?.rating??5,isBlocked:customer?.isBlocked||false,createdAt:order.createdAt,orders:[],accounts:[]};groups.set(key,group)}
  for(const alias of [customerPhone,orderPhone].filter(Boolean)){const other=groups.get(alias);if(other&&other!==group){group.orders.push(...other.orders);group.accounts.push(...other.accounts);if(group.email?.endsWith('@guest.stap.invalid')&&!other.email?.endsWith('@guest.stap.invalid'))Object.assign(group,{id:other.id,name:other.name,email:other.email,phone:other.phone,rating:other.rating,isBlocked:other.isBlocked,createdAt:other.createdAt});for(const [k,v] of groups)if(v===other)groups.set(k,group)}groups.set(alias,group)}
  if(customer?.id&&!group.accounts.includes(customer.id))group.accounts.push(customer.id);if(!group.orders.some(item=>item.id===order.id))group.orders.push(order)}
 const result=[...new Set(groups.values())].map(group=>{group.orders.sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));const ratings=group.orders.flatMap(order=>order.ratings||[]),customerRatings=ratings.filter(r=>r.toUser?.role==='CUSTOMER'),ratingAverage=customerRatings.length?customerRatings.reduce((sum,r)=>sum+r.score,0)/customerRatings.length:Number(group.rating??5),completed=group.orders.filter(order=>order.status==='COMPLETED');return {...group,rating:ratingAverage,ratingCount:customerRatings.length,ratings,totalOrders:group.orders.length,completedOrders:completed.length,cancelledOrders:group.orders.filter(order=>order.status==='CANCELLED').length,totalSpentAmd:completed.reduce((sum,order)=>sum+order.fareAmd,0)}}).sort((a,b)=>new Date(b.orders[0]?.createdAt||b.createdAt)-new Date(a.orders[0]?.createdAt||a.createdAt));
 res.json({customers:result,total:result.length,totalOrders:orders.length});
}));
app.get('/api/admin/orders/history', auth, only('ADMIN'), asyncRoute(async (req,res)=>{
  const orders=await prisma.order.findMany({orderBy:{createdAt:'desc'},include:{
    customer:{select:{id:true,name:true,phone:true,rating:true}},
    driver:{select:{id:true,name:true,phone:true,isVerified:true}}
  }});
  res.json({orders:await withCustomerOrderNumbers(orders)});
}));

app.get('/api/admin/orders/archive',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const phoneDigits=String(req.query.phone||'').replace(/\D/g,'');
 const status=String(req.query.status||'ARCHIVE').toUpperCase();
 const allowed=['ARCHIVE','ALL','COMPLETED','CANCELLED','OPEN','ACCEPTED','IN_PROGRESS'];
 if(!allowed.includes(status))return res.status(400).json({error:'Ընտրեք ճիշտ կարգավիճակ։'});
 if(phoneDigits&&phoneDigits.length<3)return res.status(400).json({error:'Հեռախոսահամարի որոնման համար մուտքագրեք առնվազն 3 թվանշան։'});
 const where=status==='ARCHIVE'?{status:{in:['COMPLETED','CANCELLED']}}:status==='ALL'?{}:{status};
 const orders=await prisma.order.findMany({where,orderBy:{createdAt:'desc'},take:500,include:{
  customer:{select:{id:true,name:true,phone:true,rating:true}},
  driver:{select:{id:true,name:true,phone:true,isVerified:true}}
 }});
 const orderCodeDigits=String(req.query.code||'').replace(/\\D/g,'');const filtered=orderCodeDigits.length===4?orders.filter(order=>String(order.orderCode||'')===orderCodeDigits):phoneDigits?orders.filter(order=>[order.phonePrimary,order.phoneSecondary,order.customer?.phone,order.driver?.phone].some(value=>String(value||'').replace(/\\D/g,'').includes(phoneDigits))):orders;
 res.json({orders:await withCustomerOrderNumbers(filtered),total:filtered.length,phoneSearch:phoneDigits||null,status});
}));
app.post('/api/admin/orders/:id/cancel', auth, only('ADMIN'), asyncRoute(async (req,res)=>{
  const existing=await prisma.order.findUnique({where:{id:req.params.id}});
  if(!existing)return res.status(404).json({error:'Պատվերը չի գտնվել։'});
  if(existing.status==='CANCELLED')return res.status(409).json({error:'Պատվերն արդեն չեղարկված է։'});
  const changed=await prisma.order.updateMany({
    where:{id:existing.id,status:{not:'CANCELLED'}},
    data:{status:'CANCELLED'}
  });
  if(!changed.count)return res.status(409).json({error:'Պատվերի կարգավիճակն արդեն փոխվել է։ Թարմացրեք ցանկը։'});
  const order=await prisma.order.findUnique({where:{id:existing.id},include:{
    customer:{select:{id:true,name:true,phone:true,rating:true}},
    driver:{select:{id:true,name:true,phone:true}}
  }});
  const drivers=await prisma.user.findMany({where:{role:'DRIVER',isVerified:true,isBlocked:false},select:{id:true}});
  const admins=await prisma.user.findMany({where:{role:'ADMIN'},select:{id:true}});
  const recipients=[...new Set([order.customerId,order.driverId,...drivers.map(x=>x.id),...admins.map(x=>x.id)].filter(Boolean))];
  const title='Պատվերը չեղարկվել է';
  const message='Պատվեր #'+String(order.orderCode||'----').padStart(4,'0')+' չեղարկվել է ադմինի կողմից։ '+order.pickupAddress+' → '+order.destinationAddress;
  if(recipients.length){
    await prisma.notification.createMany({data:recipients.map(userId=>({userId,title,message,type:'ORDER_CANCELLED'}))});
    for(const userId of recipients)io.to('user:'+userId).emit('notification:new',{title,message,type:'ORDER_CANCELLED',orderId:order.id,createdAt:new Date()});
  }
  io.to('drivers').emit('order:cancelled',{id:order.id,status:'CANCELLED',title,message});
  io.to('order:'+order.id).emit('order:cancelled',{id:order.id,status:'CANCELLED',title,message});
  emitOrderStatusChange(order,'CANCELLED',message);
  res.json({success:true,order,message:'Պատվերը չեղարկվեց։ Ուղևորը, վարորդները և ադմինը ծանուցվեցին։'});
}));

app.post('/api/admin/orders', auth, only('ADMIN'), asyncRoute(async (req,res)=>{
  const input=z.object({
    pickupDistrict:z.string().trim().min(2).max(80),
    destinationDistrict:z.string().trim().min(2).max(80),
    fareAmd:z.number().int().min(1000).max(1000000).optional(),extraChargeAmd:z.number().int().min(0).max(1000000).default(0),isUrgent:z.boolean().default(false),
    phonePrimary:z.string().trim().min(5).max(30),
    phoneSecondary:z.string().trim().min(5).max(30).optional().or(z.literal('')),
    passengerCount:z.number().int().min(1).max(8).default(1),
    transmissionType:z.enum(['AUTOMATIC','MANUAL']).default('AUTOMATIC'),
    vehicleFuelType:z.enum(['PETROL','ELECTRIC','HYBRID']).default('PETROL'),
    scheduleType:z.enum(['NOW','TODAY','TOMORROW','SCHEDULED']).default('NOW'),
    scheduledAt:z.string().datetime().optional(),
    note:z.string().max(1000).optional(),
    pickupNote:z.string().trim().max(500).optional().or(z.literal('')),
    destinationNote:z.string().trim().max(500).optional().or(z.literal('')),
    dispatchMode:z.enum(['NETWORK','CATEGORY','DIRECT']).default('NETWORK'),
    driverId:z.string().optional().or(z.literal('')),
    isTest:z.boolean().default(false)
  }).parse(req.body);
  if(input.scheduleType!=='NOW'&&!input.scheduledAt)return res.status(400).json({error:'Ընտրեք պատվերի ամսաթիվն ու ժամը։'});
  const scheduledAt=input.scheduleType==='NOW'?null:new Date(input.scheduledAt);
   const isUrgent=input.scheduleType==='NOW'?input.isUrgent:(scheduledAt.getTime()>Date.now()+60*60*1000&&input.isUrgent);
  if(scheduledAt&&scheduledAt.getTime()<=Date.now())return res.status(400).json({error:'Պատվերի նախատեսված ժամը պետք է լինի ապագայում։'});
  const route=await calculateYerevanDistrictFare(input.pickupDistrict,input.destinationDistrict);
  const pickupAddress=route.pickupDistrict+' վարչական շրջան',destinationAddress=route.destinationDistrict+' վարչական շրջան';
  const demandEligibleUrgent=isUrgent&&input.scheduleType==='NOW';
  const demand=await getUrgentDemandCoefficient(demandEligibleUrgent);
  const demandExtraChargeAmd=calculateUrgentDemandCharge(route.baseFareAmd,input.extraChargeAmd,demandEligibleUrgent,demand.demandCoefficientPercent);
  const urgentExtraChargeAmd=isUrgent?2500+demandExtraChargeAmd:0;
  const fareAmd=route.baseFareAmd+input.extraChargeAmd+urgentExtraChargeAmd;
  let driverId=null, eligibleDrivers=[];
  const driverWhere={role:'DRIVER',isVerified:true,isBlocked:false};
  if(input.dispatchMode==='DIRECT'){
    if(!input.driverId)return res.status(400).json({error:'Ընտրեք կոնկրետ վարորդ։'});
    const driver=await prisma.user.findFirst({where:{id:input.driverId,...driverWhere}});
    if(!driver)return res.status(400).json({error:'Ընտրված վարորդը հաստատված կամ ակտիվ չէ։'});
    if(input.transmissionType==='MANUAL'&&driver.driverTransmission!=='MANUAL')return res.status(400).json({error:'Ընտրված վարորդը չի վարում մեխանիկական փոխանցման տուփով մեքենա։'});
    driverId=driver.id;
    eligibleDrivers=[driver];
  } else if(input.dispatchMode==='CATEGORY'){
    eligibleDrivers=await prisma.user.findMany({where:{...driverWhere,...(input.transmissionType==='MANUAL'?{driverTransmission:'MANUAL'}:{})},select:{id:true}});
    if(!eligibleDrivers.length)return res.status(400).json({error:'Այս կարգով և փոխանցման տուփով ակտիվ հաստատված վարորդներ չկան։'});
  }
  const customerPhone=normalizePhone(input.phonePrimary);
  if(customerPhone.replace(/\D/g,'').length<7)return res.status(400).json({error:'Մուտքագրեք պատվիրատուի ճիշտ հեռախոսահամարը։'});
  // Resolve the customer by the phone entered by the administrator.
  let customer=(await prisma.user.findMany({where:{role:'CUSTOMER'},select:{id:true,phone:true}}))
    .find(user=>normalizePhone(user.phone)===customerPhone);
  if(!customer){
    const email=guestEmailForPhone(customerPhone);
    customer=await prisma.user.findUnique({where:{email}});
    if(!customer)customer=await prisma.user.create({data:{
      name:'Պատվիրատու '+customerPhone,email,phone:customerPhone,
      passwordHash:await bcrypt.hash(randomBytes(32).toString('hex'),12),role:'CUSTOMER'
    }});
  }
  let order;
  try {
    order=await prisma.order.create({data:{
      orderCode:await generateUniqueOrderCode(),customerId:customer.id,driverId,dispatchMode:input.dispatchMode,isTest:input.isTest,isUrgent,urgentExtraChargeAmd,demandCoefficientChargeAmd:demandExtraChargeAmd,requiredLicenseCategory:'',pickupAddress,
      destinationAddress,routeDistricts:route.routeDistricts,routeNeighborhoods:[],routeDistanceMeters:null,fareAmd,phonePrimary:customerPhone,phoneSecondary:input.phoneSecondary||null,passengerCount:input.passengerCount,
      transmissionType:input.transmissionType,
      vehicleFuelType:input.vehicleFuelType,scheduleType:input.scheduleType,scheduledAt,note:input.note,pickupNote:input.pickupNote||null,destinationNote:input.destinationNote||null
    }});
  } catch(error) {
    console.error('Admin order creation failed:',{code:error.code,message:error.message,meta:error.meta});
    if(error.code==='P2021'||error.code==='P2022')return res.status(503).json({error:'Պատվերների տվյալների բազայի կառուցվածքը դեռ չի թարմացվել։ Render-ում կատարեք Manual Deploy → Deploy latest commit։'});
    if(error.code==='P2003')return res.status(400).json({error:'Պատվերի կապակցված հաշիվը չի գտնվել։ Թարմացրեք էջը և կրկին փորձեք։'});
    throw error;
  }
  if(!scheduledAt){
    if(input.dispatchMode==='NETWORK')await emitNetworkOrderToEligibleDrivers({id:order.id,isTest:order.isTest});
    else await emitOrderToEligibleDrivers(eligibleDrivers,{id:order.id,isTest:order.isTest});
  }
  const message=input.dispatchMode==='DIRECT'?'Պատվերը նշանակվեց ընտրված վարորդին։':input.dispatchMode==='CATEGORY'?'Պատվերը տեղադրվեց ցանցում՝ ըստ վարորդական կարգի։':'Պատվերը տեղադրվեց վարորդների ընդհանուր ցանցում։';
  res.status(201).json({order,routeDistricts:route.routeDistricts,districtCount:route.districtCount,message});
}));
async function generateUniqueOrderCode(){for(let attempt=0;attempt<40;attempt++){const code=1000+(randomBytes(4).readUInt32BE(0)%9000);const exists=await prisma.order.findUnique({where:{orderCode:code},select:{id:true}});if(!exists)return code;}throw new Error('Չհաջողվեց ստեղծել պատվերի եզակի քառանիշ կոդ։');}
let orderCodeBackfillPromise=null;
async function ensureAllOrderCodes(){
 if(!orderCodeBackfillPromise){
  orderCodeBackfillPromise=(async()=>{
   const legacy=await prisma.order.findMany({where:{OR:[{orderCode:null},{orderCode:{lt:1000}},{orderCode:{gt:9999}}]},select:{id:true}});
   for(const order of legacy){
    const orderCode=await generateUniqueOrderCode();
    await prisma.order.update({where:{id:order.id},data:{orderCode}});
   }
   return legacy.length;
  })().catch(error=>{orderCodeBackfillPromise=null;throw error});
 }
 return orderCodeBackfillPromise;
}
async function ensureOrderCodes(orders){
 await ensureAllOrderCodes();
 if(!orders?.length)return orders||[];
 const result=[];
 for(const order of orders){
  if(Number.isInteger(order.orderCode)&&order.orderCode>=1000&&order.orderCode<=9999){result.push(order);continue;}
  const orderCode=await generateUniqueOrderCode();
  const updated=await prisma.order.update({where:{id:order.id},data:{orderCode},select:{orderCode:true}});
  result.push({...order,...updated});
 }
 return result;
}
async function withCustomerOrderNumbers(orders){if(!orders?.length)return orders||[];orders=await ensureOrderCodes(orders);const customerIds=[...new Set(orders.map(order=>order.customerId).filter(Boolean))];if(!customerIds.length)return orders;const history=await prisma.order.findMany({where:{customerId:{in:customerIds}},select:{id:true,customerId:true,createdAt:true},orderBy:[{createdAt:'asc'},{id:'asc'}]});const stats=new Map();for(const item of history){const current=stats.get(item.customerId)||{total:0,numbers:new Map()};current.total++;current.numbers.set(item.id,current.total);stats.set(item.customerId,current)}return orders.map(order=>{const current=stats.get(order.customerId);return current?{...order,customerOrderNumber:current.numbers.get(order.id)||current.total,customerOrderTotal:current.total}:order})}
function maskDriverOrderContacts(order,now=new Date()){
 if(!order)return order;
 const scheduled=order.scheduleType!=='NOW'&&order.scheduledAt?new Date(order.scheduledAt):null;
 const revealAt=scheduled?new Date(scheduled.getTime()-3*60*60*1000):null;
 const isOpen=order.status==='OPEN'||order.status==='SKIPPED';
 const closedAt=order.status==='COMPLETED'&&order.completedAt?new Date(order.completedAt):order.status==='CANCELLED'?new Date(order.updatedAt||order.createdAt):null;
 const closedContactsExpired=Boolean(closedAt)&&now.getTime()>=closedAt.getTime()+6*60*60*1000;
 const contactHidden=isOpen||(Boolean(revealAt)&&now<revealAt)||closedContactsExpired;
 if(!contactHidden)return order;
 return {...order,phonePrimary:null,phoneSecondary:null,note:null,pickupNote:closedContactsExpired?order.pickupNote:null,destinationNote:closedContactsExpired?order.destinationNote:null,customer:order.customer?{...order.customer,phone:null}:order.customer,contactHidden:true,contactRevealAt:closedContactsExpired?null:revealAt?.toISOString()||null,contactHiddenReason:closedContactsExpired?'CLOSED_RETENTION_EXPIRED':isOpen?'WAITING_FOR_ACCEPTANCE':'SCHEDULED'};
}
app.get('/api/orders/open', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const periodic = periodicVerificationState(req.user);
  if (periodic.required) return res.json({orders:[],periodicVerificationRequired:true,periodicVerificationStatus:periodic.status,periodicVerificationDueAt:periodic.dueAt});
  const categories=req.user.driverLicenseCategories||[];
  const orders = await prisma.order.findMany({
    where: {
      status:'OPEN',
      ...(req.user.driverDeliveryEnabled?{}:{NOT:{serviceId:'premium-delivery'}}),
      skippedBy:{none:{driverId:req.user.id}},
      OR:[
        {dispatchMode:'NETWORK',driverId:null},
        ...(categories.length?[{dispatchMode:'CATEGORY',driverId:null,OR:[{requiredLicenseCategory:{in:categories}},{requiredLicenseCategory:''}]}]:[]),
        ...((req.user.driverServiceCapabilities||[]).length?[{dispatchMode:'CAPABILITY',driverId:null,serviceCapability:{in:req.user.driverServiceCapabilities}}]:[]),
        {dispatchMode:'DIRECT',driverId:req.user.id}
      ],
      ...(req.user.driverTransmission==='MANUAL'?{}:{transmissionType:'AUTOMATIC'})
    },
    orderBy:[{scheduleType:'asc'},{scheduledAt:'asc'},{createdAt:'desc'}],
    include:{customer:{select:{id:true,name:true,phone:true,rating:true}}}
  });
  res.json({orders:await withCustomerOrderNumbers(orders.map(order=>maskDriverOrderContacts(order)))});
}));
function maskDriverOrderEvidence(order){
 if(!order)return order;
 const trim=report=>report?{...report,photos:undefined,passportPhotos:undefined,damagePhotos:undefined,customerSignature:undefined,passportPhotoCount:Array.isArray(report.passportPhotos)?report.passportPhotos.length:0,damagePhotoCount:Array.isArray(report.damagePhotos)?report.damagePhotos.length:0}:null;
 return {...order,vehicleInspectionReport:trim(order.vehicleInspectionReport),vehicleReturnInspection:trim(order.vehicleReturnInspection)};
}
app.get('/api/orders/mine', auth, asyncRoute(async (req, res) => {
  if (req.user.role === 'DRIVER') {
    const [assigned, skipped] = await Promise.all([
      prisma.order.findMany({ where: { driverId: req.user.id }, orderBy: { createdAt: 'desc' }, include: { customer: { select: { id: true, name: true, phone: true, rating: true } } } }),
      prisma.skippedOrder.findMany({ where: { driverId: req.user.id }, include: { order: { include: { customer: { select: { id: true, name: true, phone: true, rating: true } } } } }, orderBy: { createdAt: 'desc' } })
    ]);
    const orders = [...assigned, ...skipped.map(x => ({ ...x.order, status: 'SKIPPED', skippedAt: x.createdAt }))].sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt));
    return res.json({orders:await withCustomerOrderNumbers(orders.map(order=>maskDriverOrderEvidence(maskDriverOrderContacts(order))))});
  }
  const where = req.user.role === 'CUSTOMER' ? { customerId: req.user.id } : {};
  const orders = await prisma.order.findMany({
    where, orderBy: { createdAt: 'desc' },
    include: req.user.role === 'CUSTOMER' ? { driver: { select: {
      id:true,name:true,rating:true,vehicleMake:true,vehicleModel:true,vehicleYear:true,vehiclePlate:true,vehicleColor:true,vehicleDocumentsStatus:true,driverFirstNameLatin:true,driverLastNameLatin:true,
      driverLicenseIssuedAt:true,driverExperienceMonths:true,driverLicenseCategories:true,driverTransmission:true,dateOfBirth:true,
      isVerified:true,driverProfilePhoto:true,phone:true
    }},ratings:{where:{fromUserId:req.user.id},select:{id:true,score:true,reasonTags:true,comment:true}}} : undefined
  });
  const safeOrders = req.user.role === 'CUSTOMER' ? orders.map(o => {
    const closedAt=o.status==='COMPLETED'&&o.completedAt?new Date(o.completedAt):o.status==='CANCELLED'?new Date(o.updatedAt||o.createdAt):null;
    const contactExpired=Boolean(closedAt)&&Date.now()>=closedAt.getTime()+6*60*60*1000;
    return ({
    ...o,
    ...(contactExpired?{phonePrimary:null,phoneSecondary:null,note:null,contactHidden:true,contactHiddenReason:'CLOSED_RETENTION_EXPIRED'}:{}),
    driver: o.driver ? {
      id:o.driver.id,name:o.driver.name,phone:contactExpired?null:o.driver.phone,rating:o.driver.rating,age:o.driver.dateOfBirth?Math.max(0,new Date().getUTCFullYear()-new Date(o.driver.dateOfBirth).getUTCFullYear()-((new Date().getUTCMonth()<new Date(o.driver.dateOfBirth).getUTCMonth()||(new Date().getUTCMonth()===new Date(o.driver.dateOfBirth).getUTCMonth()&&new Date().getUTCDate()<new Date(o.driver.dateOfBirth).getUTCDate()))?1:0)):null,
      driverFirstNameLatin:o.driver.driverFirstNameLatin,driverLastNameLatin:o.driver.driverLastNameLatin,
      driverLicenseIssuedAt:o.driver.driverLicenseIssuedAt,driverExperienceMonths:o.driver.driverExperienceMonths,driverLicenseCategories:o.driver.driverLicenseCategories,
      driverTransmission:o.driver.driverTransmission,isVerified:o.driver.isVerified,vehicle:o.serviceId==='premium-delivery'&&o.driver.vehicleDocumentsStatus==='APPROVED'?{make:o.driver.vehicleMake,model:o.driver.vehicleModel,year:o.driver.vehicleYear,plate:o.driver.vehiclePlate,color:o.driver.vehicleColor}:null,
      experienceLabel:(()=>{const m=Number.isInteger(o.driver.driverExperienceMonths)?o.driver.driverExperienceMonths:(o.driver.driverLicenseIssuedAt?Math.max(0,Math.floor((Date.now()-new Date(o.driver.driverLicenseIssuedAt).getTime())/(30.4375*86400000))):null);return m===null?'Նշված չէ':(Math.floor(m/12)?Math.floor(m/12)+' տարի ':'')+(m%12?m%12+' ամիս':'')||'0 ամիս'})(),profilePhoto:o.driver.driverProfilePhoto ? 'data:image/jpeg;base64,'+decryptPrivate(o.driver.driverProfilePhoto).toString('base64') : null
    } : null,
    ...(contactExpired?{contactHidden:true}: {})
    });
   }) : orders;
  res.json({ orders: await withCustomerOrderNumbers(safeOrders) });
}));

app.post('/api/orders/:id/rate-driver',auth,only('CUSTOMER'),asyncRoute(async(req,res)=>{
 const input=z.object({score:z.number().int().min(1).max(5),reasonTags:z.array(z.string().trim().min(1).max(100)).max(8).default([]),comment:z.string().trim().max(500).optional().or(z.literal(''))}).parse(req.body);
 if(input.score<=3&&!input.reasonTags.length)return res.status(400).json({error:'Ցածր գնահատականի դեպքում պատճառ ընտրելը պարտադիր է։'});
 const result=await prisma.$transaction(async tx=>{
  const order=await tx.order.findFirst({where:{id:req.params.id,customerId:req.user.id,status:'COMPLETED',driverId:{not:null}}});
  if(!order)return {error:'Գնահատել կարելի է միայն ավարտված պատվերի վարորդին։'};
  const existing=await tx.rating.findUnique({where:{orderId_fromUserId:{orderId:order.id,fromUserId:req.user.id}}});
  if(existing)return {error:'Այս պատվերի համար արդեն գնահատական եք տվել։'};
  await tx.rating.create({data:{orderId:order.id,fromUserId:req.user.id,toUserId:order.driverId,score:input.score,reasonTags:input.reasonTags,comment:input.comment||null}});
  const aggregate=await tx.rating.aggregate({where:{toUserId:order.driverId},_avg:{score:true}});
  const rating=aggregate._avg.score===null?5:Number(aggregate._avg.score.toFixed(2));
  await tx.user.update({where:{id:order.driverId},data:{rating}});
  return {rating,driverId:order.driverId};
 });
 if(result.error)return res.status(409).json({error:result.error});
 io.emit('rating:updated',{driverId:result.driverId,rating:result.rating});
 res.json({success:true,rating:result.rating,message:'Վարորդի գնահատականը պահպանվեց։ Շնորհակալություն։'});
}));

app.post('/api/orders/:id/skip', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const order = await prisma.order.findFirst({ where: { id: req.params.id, status: 'OPEN', OR: [{ driverId: null }, { driverId: req.user.id }] } });
  if (!order) return res.status(404).json({ error: 'Բաց պատվերը չի գտնվել' });
  await prisma.skippedOrder.upsert({
    where: { orderId_driverId: { orderId: order.id, driverId: req.user.id } },
    update: {},
    create: { orderId: order.id, driverId: req.user.id }
  });
  res.json({ success: true, message: 'Պատվերը նշվեց որպես բաց թողնված։' });
}));

app.post('/api/orders/:id/cancel', auth, only('CUSTOMER'), asyncRoute(async (req, res) => {
  const existing=await prisma.order.findFirst({where:{id:req.params.id,customerId:req.user.id}});
  if(!existing)return res.status(404).json({error:'Պատվերը չի գտնվել։'});
  if(existing.scheduleType!=='NOW')return res.status(403).json({error:'Նախնական պատվերը կարող է չեղարկել միայն ադմինը։'});
  const result = await prisma.order.updateMany({
    where: { id: req.params.id, customerId: req.user.id, scheduleType:'NOW', status: { in: ['OPEN', 'ACCEPTED', 'ARRIVED'] } },
    data: { status: 'CANCELLED' }
  });
  if (!result.count) return res.status(409).json({ error: 'Պատվերը հնարավոր չէ չեղարկել այս կարգավիճակում' });
  emitOrderStatusChange(existing,'CANCELLED','Պատվիրատուն չեղարկել է պատվերը։');
  res.json({ success: true, message: 'Պատվերը չեղարկվեց։' });
}));

app.post('/api/orders/:id/accept', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const requestedOrder = await prisma.order.findFirst({ where: { id: req.params.id, status: 'OPEN', OR: [{ driverId: null }, { driverId: req.user.id }] } });
  if (!requestedOrder) return res.status(409).json({ error: 'Պատվերն արդեն ընդունվել է կամ հասանելի չէ' });
  if (periodicVerificationState(req.user).required) return res.status(403).json({error:'72 ժամը լրացել է։ Պատվերները կբացվեն մեքենայի արտաքին լուսանկարների և դեմքի սելֆիի ստուգումից հետո։',periodicVerificationRequired:true});
  if(requestedOrder.serviceId==='premium-delivery'&&!req.user.driverDeliveryEnabled)return res.status(403).json({error:'Առաքման պատվեր ընդունելու համար նախ ակտիվացրեք «ԱՌԱՔԻՉ» ռեժիմը։'});
  // Legacy license/capability/transmission metadata must not block accepting an order.
  // Accepting an order must not be blocked by legacy license-category or transmission metadata.
  // Dispatch visibility/assignment is handled separately when the order is created.
  const settingsRow = await prisma.siteContent.findUnique({ where: { id: 'main' } });
  const rawMinimum = settingsRow?.content?.minDriverBalanceAmd;
  const minimumBalanceAmd = Number.isInteger(Number(rawMinimum)) && Number(rawMinimum) >= 0 ? Number(rawMinimum) : 0;
  const personalNegativeLimitAmd = Number.isInteger(req.user.driverNegativeBalanceLimitAmd) ? req.user.driverNegativeBalanceLimitAmd : 0;
  const minimumAllowedBalanceAmd = personalNegativeLimitAmd > 0 ? -personalNegativeLimitAmd : minimumBalanceAmd;
  let result;
  try {
    result = await prisma.$transaction(async tx => {
      // Serialize this driver's accept operations so simultaneous taps cannot bypass the daily tier.
      const driverLock = await tx.user.updateMany({ where: { id: req.user.id }, data: { updatedAt: new Date() } });
      if (!driverLock.count) throw new Error("DRIVER_ACCOUNT_NOT_FOUND");
      const acceptedAt = new Date();
      // Armenia local day (UTC+4): count earlier accepted surcharge orders, excluding cancelled ones.
      const yerevanNow = new Date(acceptedAt.getTime() + 4 * 60 * 60 * 1000);
      const dayStart = new Date(Date.UTC(yerevanNow.getUTCFullYear(), yerevanNow.getUTCMonth(), yerevanNow.getUTCDate()) - 4 * 60 * 60 * 1000);
      const nextDayStart = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);
      const previousCompletedSurchargeOrders = requestedOrder.isTest || !(requestedOrder.urgentExtraChargeAmd > 0)
        ? 0
        : await tx.order.count({ where: {
            driverId: req.user.id, isTest: false, status: { in: ['ACCEPTED', 'ARRIVED', 'IN_PROGRESS', 'COMPLETED'] },
            urgentExtraChargeAmd: { gt: 0 }, acceptedAt: { gte: dayStart, lt: nextDayStart }
          } });
      const urgentSurchargeAmd = Math.max(0, requestedOrder.urgentExtraChargeAmd || 0);
      const commissionBaseAmd = Math.max(0, requestedOrder.fareAmd - urgentSurchargeAmd);
      const serviceCommissionRate = requestedOrder.serviceId === 'premium-delivery' ? 15 : 25;
      const baseCommissionAmd = requestedOrder.isTest ? 0 : Math.round(commissionBaseAmd * serviceCommissionRate / 100);
      const surchargeCommissionAmd = requestedOrder.isTest || previousCompletedSurchargeOrders < 1
        ? 0 : Math.round(urgentSurchargeAmd * 0.01);
      const commissionAmd = baseCommissionAmd + surchargeCommissionAmd;
      const claimed = await tx.order.updateMany({
        where: { id: req.params.id, status: 'OPEN', OR: [{ driverId: null }, { driverId: req.user.id }] },
        data: { status: 'ACCEPTED', driverId: req.user.id, acceptedAt, commissionRate: requestedOrder.isTest ? 0 : serviceCommissionRate, commissionAmd, commissionSurchargeAmd: surchargeCommissionAmd, driverEarningAmd: requestedOrder.isTest ? 0 : urgentSurchargeAmd }
      });
      if (!claimed.count) return null;
      if (commissionAmd > 0) {
        const debited = await tx.user.updateMany({ where: { id: req.user.id, balanceAmd: { gte: commissionAmd + minimumAllowedBalanceAmd } }, data: { balanceAmd: { decrement: commissionAmd } } });
        if (!debited.count) throw new Error('WALLET_MINIMUM_NOT_MET');
        const description = surchargeCommissionAmd > 0
          ? 'Պատվերի միջնորդավճար՝ հիմնական արժեքի '+serviceCommissionRate+'% + հավելավճարի 1%'
          : 'Պատվերի միջնորդավճար՝ հիմնական արժեքի '+serviceCommissionRate+'%';
        await tx.walletTransaction.create({ data: { userId: req.user.id, amountAmd: -commissionAmd, type: 'ORDER_COMMISSION', description, orderId: requestedOrder.id } });
      }
      const [order, driver] = await Promise.all([
        tx.order.findUnique({ where: { id: requestedOrder.id } }),
        tx.user.findUnique({ where: { id: req.user.id }, select: { balanceAmd: true } })
      ]);
      return { order, balanceAmd: driver.balanceAmd, commissionAmd, baseCommissionAmd, surchargeCommissionAmd, previousCompletedSurchargeOrders };
    });
  } catch (error) {
    if (error.message === 'WALLET_MINIMUM_NOT_MET') return res.status(409).json({ error: 'Հաշվեկշիռը բավարար չէ։ Պատվերի միջնորդավճարը կգանձվի՝ հաշվի առնելով ձեր անհատական բացասական լիմիտը։' });
    console.error('[ORDER_ACCEPT_FAILED]', { orderId: req.params.id, driverId: req.user.id, code: error.code || null, message: error.message, meta: error.meta || null });
    throw error;
  }
  if (!result) return res.status(409).json({ error: 'Պատվերն արդեն ընդունվել է կամ հասանելի չէ' });
  io.to('user:'+req.user.id).emit('driver:balance-updated',{driverId:req.user.id,balanceAmd:result.balanceAmd,updatedAt:new Date().toISOString()});
  io.emit('order:accepted', { id: result.order.id, driverId: req.user.id, status: result.order.status });
  emitOrderStatusChange(result.order,'ACCEPTED','Վարորդը ընդունել է պատվերը։');
  res.json({...result,order:maskDriverOrderContacts(result.order)});
}));

app.patch('/api/orders/:id/arrival-estimate',auth,only('DRIVER'),verifiedDriver,asyncRoute(async(req,res)=>{
 const {minutes}=z.object({minutes:z.number().int().refine(v=>[10,20,30,40,50,60].includes(v))}).parse(req.body);
 const order=await prisma.order.findFirst({where:{id:req.params.id,driverId:req.user.id,status:'ACCEPTED'},select:{id:true,customerId:true}});
 if(!order)return res.status(409).json({error:'Ժամանումը կարող եք նշել միայն ընդունված պատվերի համար։'});
 const updated=await prisma.order.update({where:{id:order.id},data:{arrivalEstimateMinutes:minutes,arrivalEstimateStatus:'PENDING',customerRequestedEtaMinutes:null}});
 await prisma.notification.create({data:{userId:order.customerId,title:'Վարորդը նշել է ժամանման ժամանակը',message:'Վարորդն առաջարկում է հասնել '+minutes+' րոպեում։ Հաստատեք, մերժեք կամ առաջարկեք ավելի երկար ժամանակ։',type:'DRIVER_ETA_PROPOSED'}});
 io.to('user:'+order.customerId).emit('order:eta-updated',{id:order.id,status:updated.arrivalEstimateStatus,minutes});
 emitOrderStatusChange({id:order.id,customerId:order.customerId,driverId:req.user.id},'ETA_UPDATED','Վարորդը կհասնի մոտ '+minutes+' րոպեից։');
 res.json({success:true,order:updated,message:'Ժամանման առաջարկն ուղարկվեց պատվիրատուին։'});
}));
app.post('/api/orders/:id/arrival-estimate-response',auth,only('CUSTOMER'),asyncRoute(async(req,res)=>{
 const input=z.object({decision:z.enum(['ACCEPTED','REJECTED','REQUEST_LONGER']),requestedMinutes:z.number().int().refine(v=>[20,30,40,50,60].includes(v)).optional()}).parse(req.body);
 const order=await prisma.order.findFirst({where:{id:req.params.id,customerId:req.user.id,status:'ACCEPTED',driverId:{not:null}}});
 if(!order||!order.arrivalEstimateMinutes||order.arrivalEstimateStatus!=='PENDING')return res.status(409).json({error:'Հաստատման սպասող առաջարկ չկա։'});
 if(input.decision==='REQUEST_LONGER'&&!input.requestedMinutes)return res.status(400).json({error:'Ընտրեք ավելի երկար ժամանակ։'});
 const status=input.decision==='REQUEST_LONGER'?'COUNTER_REQUESTED':input.decision;
 const updated=await prisma.order.update({where:{id:order.id},data:{arrivalEstimateStatus:status,customerRequestedEtaMinutes:input.decision==='REQUEST_LONGER'?input.requestedMinutes:null}});
 const title=input.decision==='ACCEPTED'?'Պատվիրատուն հաստատել է ժամանումը':input.decision==='REJECTED'?'Պատվիրատուն մերժել է ժամանման առաջարկը':'Պատվիրատուն խնդրել է ավելի երկար ժամանակ';
 const message=input.decision==='REQUEST_LONGER'?'Պատվիրատուն խնդրում է ժամանումը դարձնել '+input.requestedMinutes+' րոպե։ Նշեք նոր առաջարկ։':input.decision==='ACCEPTED'?'Պատվիրատուն հաստատել է '+order.arrivalEstimateMinutes+' րոպեն։':'Պատվիրատուն մերժել է '+order.arrivalEstimateMinutes+' րոպեանոց առաջարկը։ Նշեք նոր ժամանակ։';
 await prisma.notification.create({data:{userId:order.driverId,title,message,type:'CUSTOMER_ETA_'+input.decision}});
 io.to('user:'+order.driverId).emit('order:eta-updated',{id:order.id,status,minutes:order.arrivalEstimateMinutes,requestedMinutes:updated.customerRequestedEtaMinutes});
 emitOrderStatusChange({id:order.id,customerId:req.user.id,driverId:order.driverId},'ETA_UPDATED',message);
 res.json({success:true,order:updated,message:'Պատասխանը ուղարկվեց վարորդին։'});
}));
app.get('/api/orders/:id/inspection',auth,only('DRIVER'),verifiedDriver,asyncRoute(async(req,res)=>{const order=await prisma.order.findFirst({where:{id:req.params.id,driverId:req.user.id},select:{id:true,orderCode:true,vehicleInspectionReport:true,vehicleReturnInspection:true,vehicleInspectionPassed:true,completedAt:true}});if(!order)return res.status(404).json({error:'Պատվերը չի գտնվել ձեր պատվերներում։'});if(!order.vehicleInspectionPassed||!order.vehicleInspectionReport)return res.status(404).json({error:'Այս պատվերի զննման լուսանկարները դեռ պահպանված չեն։'});res.json({inspection:order.vehicleInspectionReport,returnInspection:order.vehicleReturnInspection,order:{id:order.id,orderCode:order.orderCode,vehicleInspectionPassed:order.vehicleInspectionPassed,completedAt:order.completedAt}});}));
app.get('/api/admin/orders/:id/inspection',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const order=await prisma.order.findUnique({where:{id:req.params.id},select:{id:true,orderCode:true,driverId:true,customerId:true,vehicleInspectionReport:true,vehicleReturnInspection:true,vehicleInspectionPassed:true,arrivedAt:true,completedAt:true}});
 if(!order)return res.status(404).json({error:'Պատվերը չի գտնվել։'});
 res.json({inspection:order.vehicleInspectionReport,returnInspection:order.vehicleReturnInspection,order:{id:order.id,orderCode:order.orderCode,driverId:order.driverId,customerId:order.customerId,vehicleInspectionPassed:order.vehicleInspectionPassed,arrivedAt:order.arrivedAt,completedAt:order.completedAt}});
}));
app.post('/api/orders/:id/inspection', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const input=z.object({
    mode:z.literal('HANDOVER').default('HANDOVER'),
    checks:z.object({exteriorChecked:z.literal(true),vehicleMatches:z.literal(true)}),
    passportPhotos:z.array(z.string().max(1800000).regex(/^data:image\/(jpeg|png|webp);base64,/)).length(2),
    hasDamage:z.boolean(),
    damagePhotos:z.array(z.string().max(1800000).regex(/^data:image\/(jpeg|png|webp);base64,/)).max(5).default([])
  }).parse(req.body);
  const order=await prisma.order.findFirst({where:{id:req.params.id,driverId:req.user.id}});
  if(!order)return res.status(404).json({error:'Պատվերը կապված չէ ձեր վարորդական հաշվի հետ։'});
  if(input.mode==='HANDOVER'){
    if(order.status!=='ARRIVED'||order.vehicleInspectionPassed)return res.status(409).json({error:'Նախ սեղմեք «Տեղում եմ»։ Զննումը հասանելի է միայն տեղ հասնելուց հետո և մեկ անգամ։'});
    if(input.checks.exteriorChecked!==true||input.checks.vehicleMatches!==true)return res.status(400).json({error:'Հաստատեք մեքենայի արտաքին զննումը և համարանիշի նույնականացումը։'});
    if(input.hasDamage&&input.damagePhotos.length===0)return res.status(400).json({error:'Վնասվածք նշելու դեպքում առնվազն մեկ լուսանկար պարտադիր է։'});
    if(!input.hasDamage&&input.damagePhotos.length>0)return res.status(400).json({error:'Վնասվածքի լուսանկարները կցելուց առաջ նշեք վնասվածքի առկայությունը։'});
    const report={...input,driverId:req.user.id,driverName:req.user.name,orderId:order.id,orderCode:order.orderCode,recordedAt:new Date().toISOString(),ip:req.ip};
    const changed=await prisma.order.updateMany({where:{id:order.id,driverId:req.user.id,status:'ARRIVED',vehicleInspectionPassed:false},data:{vehicleInspectionPassed:true,vehicleInspectionReport:report}});
    if(!changed.count)return res.status(409).json({error:'Ստուգման արձանագրությունը արդեն պահպանվել է կամ պատվերի կարգավիճակը փոխվել է։'});
    const updated=await prisma.order.findUnique({where:{id:order.id}});
    emitOrderStatusChange(updated,'ARRIVED','Մեքենայի արտաքին զննումն ու լուսանկարները պահպանվել են։');
    return res.json({order:maskDriverOrderEvidence(maskDriverOrderContacts(updated)),message:'Ստուգումն ավարտված է։ Կարող եք շարունակել պատվերը։'});
  }
  if(order.status!=='IN_PROGRESS')return res.status(409).json({error:'Վերադարձի ստուգումը հասանելի է միայն ուղևորության ընթացքում։'});
  const returnRequired=['exteriorChecked','interiorChecked','odometerChecked','belongingsChecked','keysReturned'];
  if(returnRequired.some(key=>input.checks[key]!==true))return res.status(400).json({error:'Վերադարձի ստուգման բոլոր պարտադիր կետերը պետք է հաստատվեն։'});
  const report={...input,driverId:req.user.id,driverName:req.user.name,orderId:order.id,orderCode:order.orderCode,recordedAt:new Date().toISOString(),ip:req.ip};
  const updated=await prisma.order.update({where:{id:order.id},data:{vehicleReturnInspection:report}});
  res.json({success:true,order:maskDriverOrderEvidence(maskDriverOrderContacts(updated)),message:'Մեքենայի վերադարձի վիճակը լուսանկարներով պահպանվեց։ Այժմ կարող եք ավարտել պատվերը։'});
}));

app.post('/api/orders/:id/arrive', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req,res)=>{
  const changed=await prisma.order.updateMany({where:{id:req.params.id,driverId:req.user.id,status:'ACCEPTED'},data:{status:'ARRIVED',arrivedAt:new Date()}});
  const order=await prisma.order.findFirst({where:{id:req.params.id,driverId:req.user.id}});
  if(!order)return res.status(404).json({error:'Այս պատվերը կապված չէ ձեր վարորդական հաշվի հետ։'});
  if(order.status!=='ARRIVED')return res.status(409).json({error:'Պատվերի կարգավիճակը փոխվել է։ Թարմացրեք էջը։'});
  if(changed.count)emitOrderStatusChange(order,'ARRIVED','Վարորդը հասել է պատվիրատուի նշած վայր։ Հաջորդ քայլը՝ մեքենայի զննումը։');
  res.json({order:maskDriverOrderEvidence(maskDriverOrderContacts(order)),message:'Տեղ հասնելը գրանցվեց։ Հաջորդ քայլը՝ զննում և լուսանկարներ։'});
}));

app.post('/api/orders/:id/start', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const existing = await prisma.order.findFirst({ where: { id: req.params.id, driverId: req.user.id } });
  if (!existing) return res.status(404).json({ error: 'Այս պատվերը կապված չէ ձեր վարորդական հաշվի հետ։' });
  if (existing.status === 'IN_PROGRESS') return res.json({ order: existing, message: 'Ուղևորությունն արդեն սկսված է։' });
  if (existing.status !== 'ARRIVED' || !existing.vehicleInspectionPassed || !existing.vehicleInspectionReport) return res.status(409).json({ error: 'Նախ լրացրեք մեքենայի ընդունման ստուգման արձանագրությունը և հաճախորդի հաստատումը։' });
  const changed = await prisma.order.updateMany({ where: { id: req.params.id, driverId: req.user.id, status: 'ARRIVED', vehicleInspectionPassed: true }, data: { status: 'IN_PROGRESS' } });
  const order = await prisma.order.findFirst({ where: { id: req.params.id, driverId: req.user.id } });
  if(order?.status==='IN_PROGRESS'){if(changed.count)emitOrderStatusChange(order,'IN_PROGRESS','Ուղևորությունը սկսվել է։');return res.json({order:maskDriverOrderEvidence(maskDriverOrderContacts(order)),message:changed.count?'Ուղևորությունը սկսվեց։':'Ուղևորությունն արդեն սկսված է։'});}
  return res.status(409).json({ error: 'Պատվերի կարգավիճակը փոխվել է։ Թարմացրեք էջը և կրկին փորձեք։' });
}));

app.post('/api/orders/:id/driver-cancel', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const { reason } = z.object({ reason: z.string().trim().min(3).max(500) }).parse(req.body);
  const existing=await prisma.order.findFirst({where:{id:req.params.id,driverId:req.user.id}});
  if(!existing)return res.status(404).json({error:'Պատվերը կապված չէ ձեր վարորդական հաշվի հետ։'});
  if(existing.scheduleType!=='NOW')return res.status(403).json({error:'Նախնական պատվերը կարող է չեղարկել միայն ադմինը։'});
  const changed = await prisma.order.updateMany({
    where: { id: req.params.id, driverId: req.user.id, scheduleType:'NOW', status: { in: ['ACCEPTED', 'ARRIVED'] } },
    data: { status: 'CANCELLED', driverCancellationReason: reason }
  });
  if (!changed.count) return res.status(409).json({ error: 'Այս փուլում պատվերը հնարավոր չէ չեղարկել։' });
  const order = await prisma.order.findUnique({ where: { id: req.params.id }, include: { customer: { select: { id: true, name: true } } } });
  const admins = await prisma.user.findMany({ where: { role: 'ADMIN' }, select: { id: true } });
  const recipients = [...new Set([order.customerId, ...admins.map(x => x.id)])];
  const title = 'Վարորդը չեղարկել է պատվերը';
  const message = 'Պատվեր #' + String(order.orderCode||'----').padStart(4,'0') + ' չեղարկվել է վարորդի կողմից։ Պատճառ՝ ' + reason;
  if (recipients.length) {
    await prisma.notification.createMany({ data: recipients.map(userId => ({ userId, title, message, type: 'ORDER_CANCELLED' })) });
    for (const userId of recipients) io.to('user:' + userId).emit('notification:new', { title, message, type: 'ORDER_CANCELLED', orderId: order.id, createdAt: new Date() });
  }
  io.to('order:' + order.id).emit('order:cancelled', { id: order.id, status: 'CANCELLED', title, message });
  emitOrderStatusChange(order,'CANCELLED',message);
  res.json({ success: true, message: 'Պատվերը չեղարկվեց։ Ուղևորը և ադմինը ծանուցվեցին։' });
}));


app.post('/api/orders/:id/intermediate-community', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const { community } = z.object({ community: z.enum(['Աջափնյակ','Ավան','Արաբկիր','Դավթաշեն','Էրեբունի','Քանաքեռ-Զեյթուն','Կենտրոն','Մալաթիա-Սեբաստիա','Նոր Նորք','Նորք-Մարաշ','Նուբարաշեն','Շենգավիթ']) }).parse(req.body);
  const existing = await prisma.order.findFirst({ where: { id: req.params.id, driverId: req.user.id } });
  if (!existing) return res.status(404).json({ error: 'Պատվերը կապված չէ ձեր վարորդական հաշվի հետ։' });
  if (existing.status !== 'IN_PROGRESS') return res.status(409).json({ error: 'Միջանկյալ համայնք կարելի է ավելացնել միայն ուղևորության ընթացքում։' });
  if (existing.intermediateCommunities.includes(community) || existing.pickupAddress.startsWith(community) || existing.destinationAddress.startsWith(community)) return res.status(409).json({ error: 'Այս համայնքն արդեն ներառված է երթուղում։' });
  const addedFareAmd = 2000;
  const commissionAmd = existing.isTest ? 0 : 500;
  const settingsRow = await prisma.siteContent.findUnique({ where: { id: 'main' } });
  const rawMinimum = settingsRow?.content?.minDriverBalanceAmd;
  const minimumBalanceAmd = Number.isInteger(Number(rawMinimum)) && Number(rawMinimum) >= 0 ? Number(rawMinimum) : 0;
  const personalNegativeLimitAmd = Number.isInteger(req.user.driverNegativeBalanceLimitAmd) ? req.user.driverNegativeBalanceLimitAmd : 0;
  const minimumAllowedBalanceAmd = personalNegativeLimitAmd > 0 ? -personalNegativeLimitAmd : minimumBalanceAmd;
  try {
    const result = await prisma.$transaction(async tx => {
      if (commissionAmd > 0) {
        const debited = await tx.user.updateMany({ where: { id: req.user.id, balanceAmd: { gte: commissionAmd + minimumAllowedBalanceAmd } }, data: { balanceAmd: { decrement: commissionAmd } } });
        if (!debited.count) throw new Error('WALLET_MINIMUM_NOT_MET');
      }
      const changed = await tx.order.updateMany({
        where: { id: existing.id, driverId: req.user.id, status: 'IN_PROGRESS', intermediateCommunities: { hasNot: community } },
        data: { fareAmd: { increment: addedFareAmd }, commissionAmd: { increment: commissionAmd }, intermediateCommunities: { push: community } }
      });
      if (!changed.count) throw new Error('INTERMEDIATE_COMMUNITY_ALREADY_ADDED');
      if (commissionAmd > 0) await tx.walletTransaction.create({ data: { userId: req.user.id, amountAmd: -commissionAmd, type: 'ORDER_COMMISSION', description: 'Միջանկյալ համայնքի հավելավճարի միջնորդավճար՝ ' + community, orderId: existing.id } });
      const [order, driver] = await Promise.all([tx.order.findUnique({ where: { id: existing.id } }), tx.user.findUnique({ where: { id: req.user.id }, select: { balanceAmd: true } })]);
      return { order, balanceAmd: driver.balanceAmd, commissionAmd, addedFareAmd };
    });
    io.to('user:' + req.user.id).emit('driver:balance-updated',{driverId:req.user.id,balanceAmd:result.balanceAmd,updatedAt:new Date().toISOString()});
   io.to('user:' + existing.customerId).emit('order:fare-updated', { id: existing.id, fareAmd: result.order.fareAmd, intermediateCommunities: result.order.intermediateCommunities });
    return res.json(result);
  } catch (error) {
    if (error.message === 'WALLET_MINIMUM_NOT_MET') return res.status(409).json({ error: 'Հաշվեկշիռը բավարար չէ միջանկյալ համայնքի հավելավճարի միջնորդավճարի համար։' });
    if (error.message === 'INTERMEDIATE_COMMUNITY_ALREADY_ADDED') return res.status(409).json({ error: 'Այս համայնքն արդեն ավելացվել է։ Թարմացրեք պատվերը։' });
    throw error;
  }
}));

app.post('/api/orders/:id/complete', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const input = z.object({
    score: z.number().int().min(1).max(5),
    tags: z.array(z.string().trim().min(1).max(80)).max(8).default([]),
    reasonTags: z.array(z.string().trim().min(1).max(100)).max(8).default([]),
    comment: z.string().trim().max(500).optional().or(z.literal(''))
  }).parse(req.body);
  if(input.score<=3&&!input.reasonTags.length)return res.status(400).json({error:'Ցածր գնահատականի դեպքում պատճառ ընտրելը պարտադիր է։'});
  const result = await prisma.$transaction(async tx => {
    const order = await tx.order.findFirst({ where: { id: req.params.id, driverId: req.user.id, status: 'IN_PROGRESS' } });
    if (!order) return null;
    const feedbackText = [input.tags.join(', '), input.comment].filter(Boolean).join(' — ').slice(0, 500);
    const changed = await tx.order.updateMany({
      where: { id: order.id, driverId: req.user.id, status: 'IN_PROGRESS' },
      data: { status: 'COMPLETED', completedAt: new Date(), driverFeedbackTags: input.tags, driverFeedbackComment: input.comment || null }
    });
    if (!changed.count) return null;
    await tx.rating.create({
      data: { orderId: order.id, fromUserId: req.user.id, toUserId: order.customerId, score: input.score, reasonTags: input.reasonTags, comment: [input.tags.join(', '),input.comment].filter(Boolean).join(' — ').slice(0,500)||null }
    });
    const customerRating = await tx.rating.aggregate({ where: { toUserId: order.customerId }, _avg: { score: true } });
    const updatedCustomerRating = customerRating._avg.score === null ? 5 : Number(customerRating._avg.score.toFixed(2));
    await tx.user.update({ where: { id: order.customerId }, data: { rating: updatedCustomerRating } });
    const driver = await tx.user.findUnique({ where: { id: req.user.id }, select: { balanceAmd: true } });
    return { commissionAmd: order.isTest ? 0 : order.commissionAmd, driverEarningAmd: 0, fareAmd: order.fareAmd, isTest: order.isTest, balanceAmd: driver.balanceAmd, customerRating: updatedCustomerRating, customerId: order.customerId };
  });
  if (!result) return res.status(409).json({ error: 'Պատվերը հնարավոր չէ ավարտել' });
  io.to('user:'+req.user.id).emit('driver:balance-updated',{driverId:req.user.id,balanceAmd:result.balanceAmd,updatedAt:new Date().toISOString()});
  io.emit('order:completed', { id: req.params.id });
  emitOrderStatusChange({id:req.params.id,customerId:result.customerId,driverId:req.user.id},'COMPLETED','Ուղևորությունն ավարտվել է։');
  io.emit('rating:updated', { ratedUserId: result.customerId, fromUserId: req.user.id, updatedAt: new Date().toISOString() });
  res.json({ success: true, settlement: result, balanceAmd: result.balanceAmd, message: 'Պատվերն ավարտվեց, պատվիրատուի գնահատականը պահպանվեց։' });
}));

app.patch('/api/drivers/profile', auth, only('DRIVER'), asyncRoute(async (req, res) => {
  if (req.user.isVerified) return res.status(403).json({ error: 'Վարորդական տվյալները հաստատված են․ փոփոխությունը կարող է կատարել միայն ադմինիստրատորը։' });
  const input = z.object({
    driverFirstNameLatin: z.string().trim().min(2).max(80),
    driverLastNameLatin: z.string().trim().min(2).max(80),
    driverPatronymicLatin: z.string().trim().max(80).optional().or(z.literal('')),
    driverLicenseSeries: z.string().trim().min(3).max(40),
    driverLicenseExpiresAt: z.iso.date(),
    driverLicenseIssuedAt: z.iso.date(),
    driverTransmission: z.enum(['AUTOMATIC','MANUAL'])
  }).parse(req.body);
  const user = await prisma.user.update({ where: { id: req.user.id }, data: {
    ...input,
    driverLicenseExpiresAt: new Date(input.driverLicenseExpiresAt+'T00:00:00.000Z'),
    driverLicenseIssuedAt: new Date(input.driverLicenseIssuedAt+'T00:00:00.000Z')
  }});
  res.json({ user: publicUser(user), message: 'Վարորդական տվյալները պահպանվեցին։' });
}));

app.patch('/api/admin/drivers/:id/profile', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const input = z.object({
    name: z.string().trim().min(2).max(120).optional(),
    email: z.email().optional(),
    phone: z.string().trim().min(5).max(30).optional(),
    driverFirstNameLatin: z.string().trim().min(2).max(80).optional(),
    driverLastNameLatin: z.string().trim().min(2).max(80).optional(),
    driverPatronymicLatin: z.string().trim().max(80).optional().or(z.literal('')),
    driverLicenseSeries: z.string().trim().max(40).optional(),
    driverLicenseExpiresAt: z.iso.date().optional().or(z.literal('')),
    driverLicenseIssuedAt: z.iso.date().optional().or(z.literal('')),
    driverLicenseCategories: z.array(z.string().trim().min(1).max(8)).max(20).optional(),
    driverTransmission: z.enum(['AUTOMATIC','MANUAL']).optional(),
    driverExperienceMonths: z.number().int().min(0).max(1200).optional(),
    dateOfBirth: z.iso.date().optional().or(z.literal('')),
    rating: z.number().min(0).max(5).optional(),
    driverNegativeBalanceLimitAmd: z.number().int().min(0).max(100000).optional()
  }).strict().refine(v=>Object.keys(v).length>0,'Փոփոխության տվյալներ չկան').parse(req.body);
  const driver = await prisma.user.findFirst({ where: { id: req.params.id, role: 'DRIVER' } });
  if (!driver) return res.status(404).json({ error: 'Վարորդը չի գտնվել' });
  const data={...input};
  for(const key of ['driverLicenseExpiresAt','driverLicenseIssuedAt','dateOfBirth']) if(key in data){data[key]=data[key]?new Date(data[key]+'T00:00:00.000Z'):null;}
  const user = await prisma.user.update({ where: { id: driver.id }, data });
  res.json({ user: publicUser(user), message: 'Վարորդի տվյալները թարմացվեցին ադմինի կողմից։' });
}));

app.patch('/api/drivers/capabilities',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
 const input=z.object({capabilities:z.array(z.enum(['ACCESSIBILITY_ASSIST','WHEELCHAIR_ASSIST','ELDERLY_ASSIST','CHILD_ASSIST','LUGGAGE_ASSIST'])).max(5)}).parse(req.body);
 const user=await prisma.user.update({where:{id:req.user.id},data:{driverServiceCapabilities:[...new Set(input.capabilities)]}});
 res.json({user:publicUser(user),message:'Հատուկ ծառայությունների հմտությունները պահպանվեցին։'});
}));
async function attachWalletOrderDetails(transactions){
 const orderIds=[...new Set(transactions.map(item=>item.orderId).filter(Boolean))];
 if(!orderIds.length)return transactions;
 const orders=await prisma.order.findMany({where:{id:{in:orderIds}},select:{id:true,fareAmd:true,isUrgent:true,urgentExtraChargeAmd:true,demandCoefficientChargeAmd:true,commissionAmd:true,commissionSurchargeAmd:true,commissionRate:true}});
 const byId=new Map(orders.map(order=>{const storedCoefficient=order.demandCoefficientChargeAmd||0;const legacyCoefficient=!storedCoefficient&&order.isUrgent&&(order.urgentExtraChargeAmd||0)>2500;const actualFareAmd=storedCoefficient?Math.max(0,order.fareAmd-storedCoefficient):legacyCoefficient?Math.min(order.fareAmd,Math.round((order.commissionAmd||0)/0.25)+2500):order.fareAmd;return [order.id,{id:order.id,actualFareAmd,commissionAmd:order.commissionAmd||0,commissionSurchargeAmd:order.commissionSurchargeAmd||0,commissionBaseAmd:Math.max(0,(order.commissionAmd||0)-(order.commissionSurchargeAmd||0)),commissionRate:order.commissionRate||0}]}));
 return transactions.map(item=>({...item,orderDetails:item.orderId?byId.get(item.orderId)||null:null}));
}
app.get('/api/drivers/wallet', auth, only('DRIVER'), asyncRoute(async (req, res) => {
  const transactions = await prisma.walletTransaction.findMany({
    where: { userId: req.user.id }, orderBy: { createdAt: 'desc' }, take: 100
  });
  res.json({ transactions: await attachWalletOrderDetails(transactions) });
}));

app.get('/api/admin/drivers/:id/transactions', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const transactions = await prisma.walletTransaction.findMany({
    where: { userId: req.params.id }, orderBy: { createdAt: 'desc' }
  });
  res.json({ transactions: await attachWalletOrderDetails(transactions) });
}));

app.post('/api/drivers/location', auth, only('DRIVER'), asyncRoute(async (req, res) => {
  const { latitude, longitude, orderId } = z.object({
    latitude: z.number().min(-90).max(90), longitude: z.number().min(-180).max(180),
    orderId: z.string().optional()
  }).parse(req.body);
  if (orderId) {
    const order = await prisma.order.findFirst({ where: { id: orderId, driverId: req.user.id, status: { in: ['ACCEPTED', 'IN_PROGRESS'] } } });
    if (!order) return res.status(404).json({ error: 'Ակտիվ պատվերը չի գտնվել' });
    io.to('order:' + orderId).emit('driver:location', { driverId: req.user.id, latitude, longitude, updatedAt: new Date().toISOString() });
  }
  res.json({ ok: true });
}));

app.post('/api/admin/drivers/:id/top-up', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const { amountAmd, description } = z.object({ amountAmd: z.number().int().positive().max(100000000), description: z.string().trim().min(3).max(300) }).parse(req.body);
  const driver = await prisma.user.findFirst({ where: { id: req.params.id, role: 'DRIVER' } });
  if (!driver) return res.status(404).json({ error: 'Վարորդը չի գտնվել' });
  const updated = await prisma.$transaction(async tx => {
    const user = await tx.user.update({ where: { id: driver.id }, data: { balanceAmd: { increment: amountAmd } } });
    await tx.walletTransaction.create({ data: { userId: driver.id, amountAmd, type: 'ADMIN_TOP_UP', description, createdByAdmin: req.user.id } });
    return user;
  });
  io.to('user:'+driver.id).emit('driver:balance-updated',{driverId:driver.id,balanceAmd:updated.balanceAmd,updatedAt:new Date().toISOString()});
  res.json({ driver: publicUser(updated) });
}));

app.post('/api/admin/drivers/:id/withdraw', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const { amountAmd, description } = z.object({
    amountAmd: z.number().int().positive().max(100000000),
    description: z.string().trim().min(3).max(300)
  }).parse(req.body);
  const driver = await prisma.user.findFirst({ where: { id: req.params.id, role: 'DRIVER' } });
  if (!driver) return res.status(404).json({ error: 'Վարորդը չի գտնվել' });
  const result = await prisma.$transaction(async tx => {
    const user = await tx.user.update({
      where: { id: driver.id },
      data: { balanceAmd: { decrement: amountAmd } }
    });
    await tx.walletTransaction.create({
      data: {
        userId: driver.id,
        amountAmd: -amountAmd,
        type: 'ADMIN_ADJUSTMENT',
        description,
        createdByAdmin: req.user.id
      }
    });
    return user;
  });
  io.to('user:'+driver.id).emit('driver:balance-updated',{driverId:driver.id,balanceAmd:result.balanceAmd,updatedAt:new Date().toISOString()});
  res.json({ driver: publicUser(result), message: 'Գումարը ելքագրվեց։ Հաշվեկշիռը կարող է դառնալ բացասական։' });
}));

app.patch('/api/admin/users/convert-to-driver', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const { email, driverLicense } = z.object({
    email: z.email().transform(v => v.toLowerCase()),
    driverLicense: z.string().trim().min(3).max(100)
  }).parse(req.body);
  const target = await prisma.user.findUnique({ where: { email } });
  if (!target) return res.status(404).json({ error: 'Այս էլ․ փոստով հաշիվ չի գտնվել' });
  if (target.role !== 'CUSTOMER') return res.status(409).json({ error: 'Միայն հաճախորդի հաշիվը կարելի է փոխել վարորդի հաշվի' });
  const user = await prisma.user.update({
    where: { id: target.id },
    data: { role: 'DRIVER', driverLicense: driverLicense.trim(), isVerified: false }
  });
  res.json({ success: true, user: publicUser(user), message: 'Հաշիվը փոխվեց վարորդի։ Վարորդը սպասում է ադմինի հաստատմանը։' });
}));

app.delete('/api/admin/users/by-email', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const { email } = z.object({ email: z.email().transform(v => v.toLowerCase()) }).parse(req.body);
  const target = await prisma.user.findUnique({ where: { email } });
  if (!target) return res.status(404).json({ error: 'Այս էլ․ փոստով հաշիվ չի գտնվել' });
  if (target.role === 'ADMIN') return res.status(403).json({ error: 'Ադմինի հաշիվը հեռացնել չի թույլատրվում' });
  const [customerOrders, driverOrders, transactions, ratingsGiven, ratingsReceived] = await Promise.all([
    prisma.order.count({ where: { customerId: target.id } }),
    prisma.order.count({ where: { driverId: target.id } }),
    prisma.walletTransaction.count({ where: { userId: target.id } }),
    prisma.rating.count({ where: { fromUserId: target.id } }),
    prisma.rating.count({ where: { toUserId: target.id } })
  ]);
  if (customerOrders || driverOrders || transactions || ratingsGiven || ratingsReceived) {
    return res.status(409).json({ error: 'Հաշիվը կապված է պատվերների, վճարումների կամ գնահատականների հետ և չի կարող անվտանգ ջնջվել։' });
  }
  await prisma.user.delete({ where: { id: target.id } });
  res.json({ success: true, message: 'Հաշիվը հեռացվեց, էլ․ փոստն ազատ է նոր գրանցման համար։' });
}));

app.get('/api/admin/drivers', auth, only('ADMIN'), asyncRoute(async (_req, res) => {
  const drivers = await prisma.user.findMany({ where: { role: 'DRIVER' }, orderBy: { createdAt: 'desc' }, select: { id: true, name: true, email: true, phone: true, isBlocked: true, isVerified: true, balanceAmd: true, driverFirstNameLatin: true, driverLastNameLatin: true, driverPatronymicLatin: true, driverLicenseSeries: true, driverLicenseExpiresAt: true, driverLicenseIssuedAt: true, driverExperienceMonths: true, driverLicenseCategories: true, driverTransmission: true, vehicleMake:true, vehicleModel:true, vehicleYear:true, vehiclePlate:true, vehicleDocumentsStatus:true, vehicleVerificationMessage:true, driverDeliveryEnabled:true, driverProfilePhotoStatus:true, periodicVehicleVerificationStatus:true, periodicVehicleVerificationDueAt:true, periodicVehicleVerificationSubmittedAt:true, driverDocumentsStatus: true, driverVerificationMessage: true, driverVerifiedAt: true, dateOfBirth:true, rating:true, driverNegativeBalanceLimitAmd:true, createdAt: true } });
  res.json({ drivers });
}));

app.post('/api/drivers/documents', auth, only('DRIVER'), asyncRoute(async (req, res) => {
 if(req.user.isVerified)return res.status(403).json({error:'Հաստատված փաստաթղթերը փոփոխել կարող է միայն ադմինը։'});
 if(req.user.driverDocumentsStatus==='PENDING_REVIEW')return res.status(409).json({error:'Փաստաթղթերն արդեն ուղարկված են և սպասում են ադմինի ստուգմանը։'});
 const input=z.object({front:z.string().min(100).max(3500000),back:z.string().min(100).max(3500000),selfie:z.string().min(100).max(3500000),passportDocumentType:z.enum(['PASSPORT','ID_CARD']),passportFront:z.string().min(100).max(3500000),passportBack:z.string().min(100).max(3500000)}).parse(req.body);
 const decode=value=>{const match=value.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/i);if(!match)throw new Error('Նկարը պետք է լինի JPG/JPEG։');const buffer=Buffer.from(match[1],'base64');if(buffer[0]!==0xff||buffer[1]!==0xd8||!buffer.length||buffer.length>2500000)throw new Error('Յուրաքանչյուր լուսանկարը պետք է լինի վավեր JPEG և առավելագույնը 2.5 ՄԲ։');return encryptPrivate(buffer)};
 const docs={front:decode(input.front),back:decode(input.back),selfie:decode(input.selfie),passportFront:decode(input.passportFront),passportBack:decode(input.passportBack)};
 const user=await prisma.user.update({where:{id:req.user.id},data:{driverLicenseFront:docs.front,driverLicenseBack:docs.back,driverLicenseSelfie:docs.selfie,passportDocumentType:input.passportDocumentType,passportNumberEncrypted:null,passportIssuedByEncrypted:null,dateOfBirth:null,passportIssueDate:null,passportExpiryDate:null,passportFront:docs.passportFront,passportBack:docs.passportBack,driverProfilePhoto:docs.selfie,driverOcrText:null,driverDocumentsStatus:'PENDING_REVIEW',isVerified:false,driverVerifiedAt:null,driverVerificationMessage:'Փաստաթղթերն ուղարկվել են։ Ադմինը պետք է ձեռքով ուսումնասիրի բոլոր լուսանկարները և հաստատի կամ մերժի դիմումը։',driverDocumentsPdf:encryptPrivate(makeDocumentsPdf('STAP DRIVER identity documents',[['Driver license front',docs.front],['Driver license back',docs.back],['Driver selfie',docs.selfie],[input.passportDocumentType==='PASSPORT'?'Passport photo page':'ID card front',docs.passportFront],[input.passportDocumentType==='PASSPORT'?'Passport registration page':'ID card back',docs.passportBack]].map(([label,data])=>({label,data}))))}});
 res.json({success:true,user:publicUser(user),message:'Բոլոր 5 լուսանկարներն ուղարկվել են ադմինին՝ ձեռքով ստուգման։ OCR ստուգում չի կատարվում։'});
}));
app.post('/api/drivers/vehicle',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
 const input=z.object({make:z.string().trim().min(2).max(80),model:z.string().trim().min(1).max(80),color:z.string().trim().min(2).max(60),year:z.number().int().min(1980).max(new Date().getFullYear()+1),plate:z.string().trim().min(4).max(20),front:z.string().min(100).max(3500000),back:z.string().min(100).max(3500000),left:z.string().min(100).max(3500000),right:z.string().min(100).max(3500000),registrationFront:z.string().min(100).max(3500000),registrationBack:z.string().min(100).max(3500000)}).parse(req.body);
 const decode=value=>{const m=value.startsWith('data:image/jpeg;base64,')?['',value.slice('data:image/jpeg;base64,'.length)]:null;if(!m)throw new Error('Լուսանկարները պետք է արվեն տեսախցիկով՝ JPEG ձևաչափով։');const b=Buffer.from(m[1],'base64');if(b[0]!==255||b[1]!==216||!b.length||b.length>2500000)throw new Error('Յուրաքանչյուր լուսանկարը պետք է լինի JPEG՝ առավելագույնը 2.5 ՄԲ։');return encryptPrivate(b)};
 const p={front:decode(input.front),back:decode(input.back),left:decode(input.left),right:decode(input.right),registrationFront:decode(input.registrationFront),registrationBack:decode(input.registrationBack)};
 const user=await prisma.user.update({where:{id:req.user.id},data:{vehicleMake:input.make,vehicleModel:input.model,vehicleYear:input.year,vehiclePlate:input.plate,vehicleColor:input.color,vehiclePhotosFront:p.front,vehiclePhotosBack:p.back,vehiclePhotosLeft:p.left,vehiclePhotosRight:p.right,vehicleRegistrationFront:p.registrationFront,vehicleRegistrationBack:p.registrationBack,vehicleDocumentsStatus:'NOT_REQUIRED',vehicleVerificationMessage:'Մեքենայի տվյալները պահպանվել են։ Պարտադիր պարբերական ստուգումը կպահանջվի 72 ժամից։'}});
 res.json({success:true,user:publicUser(user),message:'Մեքենայի տվյալներն ու 6 լուսանկարները պահպանվեցին։ Նախնական ադմինյան մեքենայի հաստատում այլևս պետք չէ․ 72 ժամից կպահանջվի պարբերական լուսանկարային ստուգում։'});
}));
app.patch('/api/drivers/delivery-mode',auth,only('DRIVER'),verifiedDriver,asyncRoute(async(req,res)=>{
 const enabled=z.object({enabled:z.boolean()}).parse(req.body).enabled;
 if(enabled&&(!req.user.vehicleMake||!req.user.vehicleModel||!req.user.vehiclePlate))return res.status(409).json({error:'Առաքիչ ռեժիմը միացնելու համար լրացրեք մեքենայի տվյալները։'});
 const user=await prisma.user.update({where:{id:req.user.id},data:{driverDeliveryEnabled:enabled}});
 res.json({success:true,user:publicUser(user),message:enabled?'Առաքիչ ռեժիմն ակտիվ է։':'Առաքիչ ռեժիմն անջատված է։'});
}));
app.patch('/api/admin/drivers/:id/delivery-mode',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const enabled=z.object({enabled:z.boolean()}).parse(req.body).enabled;
 const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել։'});
 if(enabled&&(!driver.vehicleMake||!driver.vehicleModel||!driver.vehiclePlate))return res.status(409).json({error:'Նախ լրացրեք վարորդի մեքենայի տվյալները։'});
 const user=await prisma.user.update({where:{id:driver.id},data:{driverDeliveryEnabled:enabled}});
 await prisma.notification.create({data:{userId:driver.id,title:enabled?'Առաքիչ ծառայությունն ակտիվացվել է':'Առաքիչ ծառայությունն անջատվել է',message:enabled?'Ադմինը միացրել է ձեր Առաքիչ ծառայությունը։':'Ադմինը անջատել է ձեր Առաքիչ ծառայությունը։',type:'DELIVERY_MODE'}});
 res.json({success:true,driver:publicUser(user),message:enabled?'Առաքիչ ծառայությունը միացված է վարորդի համար։':'Առաքիչ ծառայությունն անջատված է։'});
}));
app.get('/api/admin/drivers/:id/vehicle',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const d=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'},select:{id:true,name:true,vehicleMake:true,vehicleModel:true,vehicleYear:true,vehiclePlate:true,vehicleColor:true,driverProfilePhotoStatus:true,vehicleDocumentsStatus:true,vehiclePhotosFront:true,vehiclePhotosBack:true,vehiclePhotosLeft:true,vehiclePhotosRight:true,vehicleRegistrationFront:true,vehicleRegistrationBack:true}});
 if(!d)return res.status(404).json({error:'Վարորդը չի գտնվել։'});
 const image=b=>b?'data:image/jpeg;base64,'+decryptPrivate(b).toString('base64'):null;
 res.json({vehicle:{...d,photos:{front:image(d.vehiclePhotosFront),back:image(d.vehiclePhotosBack),left:image(d.vehiclePhotosLeft),right:image(d.vehiclePhotosRight)},registration:{front:image(d.vehicleRegistrationFront),back:image(d.vehicleRegistrationBack)}}});
}));
app.patch('/api/admin/drivers/:id/vehicle/review',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const {decision,reason}=z.object({decision:z.enum(['APPROVED','REJECTED']),reason:z.string().trim().max(500).optional()}).parse(req.body);
 const d=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!d)return res.status(404).json({error:'Վարորդը չի գտնվել։'});
 if(decision==='APPROVED'&&![d.vehiclePhotosFront,d.vehiclePhotosBack,d.vehiclePhotosLeft,d.vehiclePhotosRight,d.vehicleRegistrationFront,d.vehicleRegistrationBack].every(Boolean))return res.status(409).json({error:'Բոլոր մեքենայի լուսանկարները և փաստաթղթերը պարտադիր են։'});
 if(decision==='REJECTED'&&!reason)return res.status(400).json({error:'Մերժման պատճառը պարտադիր է։'});
 const note=decision==='APPROVED'?'Մեքենան և փաստաթղթերը հաստատվել են։':'Մեքենայի տվյալները մերժվել են։ Պատճառ՝ '+reason+'։';
 const user=await prisma.user.update({where:{id:d.id},data:{vehicleDocumentsStatus:decision,vehicleVerificationMessage:note,driverDeliveryEnabled:decision==='APPROVED'?d.driverDeliveryEnabled:false}});
 await prisma.notification.create({data:{userId:d.id,title:decision==='APPROVED'?'Մեքենան հաստատված է':'Մեքենայի փաստաթղթերը մերժվել են',message:note,type:decision}});
 res.json({success:true,message:note,user:publicUser(user)});
}));
app.post('/api/drivers/periodic-verification',auth,only('DRIVER'),verifiedDriver,asyncRoute(async(req,res)=>{
 const state=periodicVerificationState(req.user);
 if(!state.required)return res.status(409).json({error:'Պարբերական ստուգման ժամկետը դեռ չի լրացել։'});
 const input=z.object({front:z.string().min(100).max(3500000),back:z.string().min(100).max(3500000),left:z.string().min(100).max(3500000),right:z.string().min(100).max(3500000),selfie:z.string().min(100).max(3500000)}).parse(req.body);
 const decode=value=>{const m=value.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/i);if(!m)throw new Error('Բոլոր նկարները պետք է լինեն JPEG ձևաչափով։');const b=Buffer.from(m[1],'base64');if(!b.length||b.length>2500000)throw new Error('Յուրաքանչյուր նկարը պետք է լինի առավելագույնը 2.5 ՄԲ։');return encryptPrivate(b)};
 const user=await prisma.user.update({where:{id:req.user.id},data:{periodicVehicleFront:decode(input.front),periodicVehicleBack:decode(input.back),periodicVehicleLeft:decode(input.left),periodicVehicleRight:decode(input.right),periodicFaceSelfie:decode(input.selfie),periodicVehicleVerificationStatus:'PENDING_REVIEW',periodicVehicleVerificationSubmittedAt:new Date()}});
 const admins=await prisma.user.findMany({where:{role:'ADMIN'},select:{id:true}});
 const message='Վարորդ '+req.user.name+' ('+req.user.phone+') ներկայացրել է 72-ժամյա մեքենայի արտաքին լուսանկարների և դեմքի սելֆիի ստուգումը։';
 if(admins.length){await prisma.notification.createMany({data:admins.map(a=>({userId:a.id,title:'72-ԺԱՄՅԱ ՎԱՐՈՐԴԻ ՍՏՈՒԳՈՒՄ',message,type:'PERIODIC_VEHICLE_REVIEW'}))});for(const admin of admins)io.to('user:'+admin.id).emit('notification:new',{title:'72-ԺԱՄՅԱ ՎԱՐՈՐԴԻ ՍՏՈՒԳՈՒՄ',message,type:'PERIODIC_VEHICLE_REVIEW',createdAt:new Date()});}
 res.json({success:true,user:publicUser(user),message:'Լուսանկարներն ուղարկվեցին ադմինին։ Մինչև հաստատումը ցանցի պատվերները փակ են։'});
}));
app.get('/api/admin/drivers/:id/periodic-verification',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const d=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'},select:{id:true,name:true,periodicVehicleVerificationStatus:true,periodicVehicleVerificationDueAt:true,periodicVehicleVerificationSubmittedAt:true,periodicVehicleFront:true,periodicVehicleBack:true,periodicVehicleLeft:true,periodicVehicleRight:true,periodicFaceSelfie:true,approvedPeriodicVehicleFront:true,approvedPeriodicVehicleBack:true,approvedPeriodicVehicleLeft:true,approvedPeriodicVehicleRight:true,approvedPeriodicFaceSelfie:true}});
 if(!d)return res.status(404).json({error:'Վարորդը չի գտնվել։'});
 const image=b=>b?'data:image/jpeg;base64,'+decryptPrivate(b).toString('base64'):null;
 res.json({verification:{...d,photos:{front:image(d.periodicVehicleFront),back:image(d.periodicVehicleBack),left:image(d.periodicVehicleLeft),right:image(d.periodicVehicleRight),selfie:image(d.periodicFaceSelfie)}}});
}));
app.patch('/api/admin/drivers/:id/periodic-verification/review',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const {decision,reason}=z.object({decision:z.enum(['APPROVED','REJECTED']),reason:z.string().trim().max(500).optional()}).parse(req.body);
 const d=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!d)return res.status(404).json({error:'Վարորդը չի գտնվել։'});
 if(d.periodicVehicleVerificationStatus!=='PENDING_REVIEW')return res.status(409).json({error:'Պարբերական ստուգման սպասող հայտ չկա։'});
 if(decision==='APPROVED'&&![d.periodicVehicleFront,d.periodicVehicleBack,d.periodicVehicleLeft,d.periodicVehicleRight,d.periodicFaceSelfie].every(Boolean))return res.status(409).json({error:'Բոլոր 4 արտաքին լուսանկարները և դեմքի սելֆին պարտադիր են։'});
 if(decision==='REJECTED'&&!reason)return res.status(400).json({error:'Մերժման պատճառը պարտադիր է։'});
 const dueAt=decision==='APPROVED'?new Date(Date.now()+DRIVER_PERIODIC_VERIFICATION_MS):d.periodicVehicleVerificationDueAt;
 const note=decision==='APPROVED'?'72-ժամյա մեքենայի լուսանկարների և դեմքի սելֆիի ստուգումը հաստատվել է։ Նոր լուսանկարները դարձել են գործող, իսկ նախորդ հաստատված տարբերակները ավտոմատ փոխարինվել են։ Պատվերների հասանելիությունը վերականգնվել է։':'72-ժամյա ստուգումը մերժվել է։ Պատճառ՝ '+reason+'։ Խնդրում ենք կրկին ուղարկել լուսանկարները։';
 const updateData=decision==='APPROVED'?{
  periodicVehicleVerificationStatus:'APPROVED',periodicVehicleVerificationDueAt:dueAt,
  approvedPeriodicVehicleFront:d.periodicVehicleFront,approvedPeriodicVehicleBack:d.periodicVehicleBack,approvedPeriodicVehicleLeft:d.periodicVehicleLeft,approvedPeriodicVehicleRight:d.periodicVehicleRight,approvedPeriodicFaceSelfie:d.periodicFaceSelfie,
  periodicVehicleFront:null,periodicVehicleBack:null,periodicVehicleLeft:null,periodicVehicleRight:null,periodicFaceSelfie:null
 }:{periodicVehicleVerificationStatus:'REJECTED'};
 const user=await prisma.user.update({where:{id:d.id},data:updateData});
 await prisma.notification.create({data:{userId:d.id,title:decision==='APPROVED'?'Պարբերական ստուգումը հաստատված է':'Պարբերական ստուգումը մերժվել է',message:note,type:'PERIODIC_VEHICLE_REVIEW_RESULT'}});
 res.json({success:true,user:publicUser(user),message:note});
}));
app.post('/api/drivers/profile-photo', auth, only('DRIVER'), asyncRoute(async(req,res)=>{
 const {photo}=z.object({photo:z.string().min(100).max(3500000)}).parse(req.body);
 const m=photo.match(/^data:image\/(jpeg|jpg|png|webp);base64,([A-Za-z0-9+/=]+)$/i);
 if(!m)return res.status(400).json({error:'Ընտրեք JPG, PNG կամ WEBP լուսանկար։'});
 const data=Buffer.from(m[2],'base64');if(!data.length||data.length>2500000)return res.status(400).json({error:'Լուսանկարը պետք է լինի առավելագույնը 2.5 ՄԲ։'});
 await prisma.user.update({where:{id:req.user.id},data:{pendingDriverProfilePhoto:encryptPrivate(data),driverProfilePhotoStatus:'PENDING_REVIEW'}});
 const admins=await prisma.user.findMany({where:{role:'ADMIN'},select:{id:true}});
 if(admins.length){const notificationMessage='Վարորդ '+req.user.name+' ուղարկել է նոր պրոֆիլի լուսանկար՝ հաստատման համար։';await prisma.notification.createMany({data:admins.map(a=>({userId:a.id,title:'Պրոֆիլի նոր լուսանկար',message:notificationMessage,type:'PROFILE_PHOTO_REVIEW'}))});for(const admin of admins)io.to('user:'+admin.id).emit('notification:new',{title:'Պրոֆիլի նոր լուսանկար',message:notificationMessage,type:'PROFILE_PHOTO_REVIEW',createdAt:new Date()});}
 res.json({success:true,message:'Լուսանկարը ուղարկվել է ադմինիստրատորին։ Գլխավոր նկարը կփոխվի միայն հաստատումից հետո։'});
}));
app.get('/api/drivers/profile-photo',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
 const p=req.user.driverProfilePhoto;
 res.json({photo:p?'data:image/jpeg;base64,'+decryptPrivate(p).toString('base64'):null,status:req.user.driverProfilePhotoStatus||'NONE'});
}));
app.post('/api/admin/drivers/:id/profile-photo/upload',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const {photo}=z.object({photo:z.string().min(100).max(3500000)}).parse(req.body);
 const m=photo.match(/^data:image\/(jpeg|jpg|png|webp);base64,([A-Za-z0-9+/=]+)$/i);
 if(!m)return res.status(400).json({error:'Ընտրեք JPG, PNG կամ WEBP լուսանկար։'});
 const data=Buffer.from(m[2],'base64');if(!data.length||data.length>2500000)return res.status(400).json({error:'Լուսանկարը պետք է լինի առավելագույնը 2.5 ՄԲ։'});
 const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել։'});
 await prisma.user.update({where:{id:driver.id},data:{pendingDriverProfilePhoto:encryptPrivate(data),driverProfilePhotoStatus:'PENDING_REVIEW'}});
 res.json({success:true,message:'Նկարը ներբեռնվեց որպես սպասող տարբերակ։ Հաստատեք այն՝ գլխավոր դարձնելու համար։'});
}));
app.patch('/api/admin/drivers/:id/profile-photo/review',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const {decision,reason}=z.object({decision:z.enum(['APPROVED','REJECTED']),reason:z.string().trim().max(500).optional()}).parse(req.body);
 const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել։'});
 if(!driver.pendingDriverProfilePhoto)return res.status(409).json({error:'Հաստատման սպասող լուսանկար չկա։'});
 if(decision==='REJECTED'&&!reason)return res.status(400).json({error:'Մերժման պատճառը պարտադիր է։'});
 const approved=decision==='APPROVED';
 await prisma.user.update({where:{id:driver.id},data:approved?{driverProfilePhoto:driver.pendingDriverProfilePhoto,pendingDriverProfilePhoto:null,driverProfilePhotoStatus:'APPROVED'}:{pendingDriverProfilePhoto:null,driverProfilePhotoStatus:'REJECTED'}});
 await prisma.notification.create({data:{userId:driver.id,title:approved?'Պրոֆիլի լուսանկարը հաստատվեց':'Պրոֆիլի լուսանկարը մերժվեց',message:approved?'Ձեր նոր լուսանկարը հաստատվել և դարձել է պրոֆիլի գլխավոր նկարը։':'Ձեր ուղարկած լուսանկարը մերժվել է։ Պատճառ՝ '+reason,type:'PROFILE_PHOTO_'+decision}});
 res.json({success:true,message:approved?'Լուսանկարը հաստատվեց և դարձավ գլխավոր նկարը։':'Լուսանկարը մերժվեց։'});
}));
app.get('/api/drivers/gallery',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
 const rows=await prisma.driverPhoto.findMany({where:{userId:req.user.id},orderBy:{createdAt:'asc'}});
 res.json({photos:rows.map(p=>({id:p.id,image:'data:image/jpeg;base64,'+decryptPrivate(p.image).toString('base64')}))});
}));
app.post('/api/drivers/gallery',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
 const {photos}=z.object({photos:z.array(z.string().min(100).max(3500000)).min(1).max(8)}).parse(req.body);
 const count=await prisma.driverPhoto.count({where:{userId:req.user.id}});
 if(count+photos.length>8)return res.status(409).json({error:'Յուրաքանչյուր վարորդի համար թույլատրվում է առավելագույնը 8 լրացուցիչ լուսանկար։ Մնացել է՝ '+Math.max(0,8-count)});
 const buffers=photos.map(value=>{const m=value.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/i);if(!m)throw new Error('Լուսանկարները պետք է լինեն JPEG։');const b=Buffer.from(m[1],'base64');if(!b.length||b.length>2500000)throw new Error('Յուրաքանչյուր լուսանկարը պետք է լինի առավելագույնը 2.5 ՄԲ։');return encryptPrivate(b)});
 await prisma.$transaction(buffers.map(image=>prisma.driverPhoto.create({data:{userId:req.user.id,image}})));
 res.json({success:true,message:'Լուսանկարները հաջողությամբ ավելացվեցին։'});
}));
app.delete('/api/drivers/gallery/:photoId',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
 const p=await prisma.driverPhoto.findFirst({where:{id:req.params.photoId,userId:req.user.id}});
 if(!p)return res.status(404).json({error:'Լուսանկարը չի գտնվել։'});
 await prisma.driverPhoto.delete({where:{id:p.id}});res.json({success:true});
}));

app.get('/api/admin/drivers/:id/verification-profile',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const d=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'},select:{
  id:true,name:true,email:true,phone:true,role:true,isVerified:true,isBlocked:true,createdAt:true,driverVerifiedAt:true,
  driverFirstNameLatin:true,driverLastNameLatin:true,driverPatronymicLatin:true,driverLicenseSeries:true,driverLicenseIssuedAt:true,driverLicenseExpiresAt:true,driverLicenseCategories:true,driverExperienceMonths:true,driverDocumentsStatus:true,driverVerificationMessage:true,driverLicenseFront:true,driverLicenseBack:true,driverLicenseSelfie:true,
  dateOfBirth:true,passportDocumentType:true,passportNumberEncrypted:true,passportIssuedByEncrypted:true,passportIssueDate:true,passportExpiryDate:true,passportFront:true,passportBack:true,
  driverProfilePhoto:true,pendingDriverProfilePhoto:true,driverProfilePhotoStatus:true,driverPhotos:{orderBy:{createdAt:'asc'}},
  vehicleMake:true,vehicleModel:true,vehicleYear:true,vehiclePlate:true,vehicleColor:true,vehicleDocumentsStatus:true,vehicleVerificationMessage:true,vehiclePhotosFront:true,vehiclePhotosBack:true,vehiclePhotosLeft:true,vehiclePhotosRight:true,vehicleRegistrationFront:true,vehicleRegistrationBack:true,
  periodicVehicleVerificationStatus:true,periodicVehicleVerificationDueAt:true,periodicVehicleVerificationSubmittedAt:true,periodicVehicleFront:true,periodicVehicleBack:true,periodicVehicleLeft:true,periodicVehicleRight:true,periodicFaceSelfie:true,approvedPeriodicVehicleFront:true,approvedPeriodicVehicleBack:true,approvedPeriodicVehicleLeft:true,approvedPeriodicVehicleRight:true,approvedPeriodicFaceSelfie:true
 }});
 if(!d)return res.status(404).json({error:'Վարորդը չի գտնվել։'});
 const image=b=>b?'data:image/jpeg;base64,'+decryptPrivate(b).toString('base64'):null;
 const {passportNumberEncrypted,passportIssuedByEncrypted,driverLicenseFront,driverLicenseBack,driverLicenseSelfie,passportFront,passportBack,driverProfilePhoto,pendingDriverProfilePhoto,driverPhotos,vehiclePhotosFront,vehiclePhotosBack,vehiclePhotosLeft,vehiclePhotosRight,vehicleRegistrationFront,vehicleRegistrationBack,periodicVehicleFront,periodicVehicleBack,periodicVehicleLeft,periodicVehicleRight,periodicFaceSelfie,approvedPeriodicVehicleFront,approvedPeriodicVehicleBack,approvedPeriodicVehicleLeft,approvedPeriodicVehicleRight,approvedPeriodicFaceSelfie,...safe}=d;
 res.json({profile:{
  ...safe,passportNumber:decryptPrivate(passportNumberEncrypted)?.toString('utf8')||null,passportIssuedBy:decryptPrivate(passportIssuedByEncrypted)?.toString('utf8')||null,
  documents:{license:{front:image(d.driverLicenseFront),back:image(d.driverLicenseBack),selfie:image(d.driverLicenseSelfie)},identity:{front:image(d.passportFront),back:image(d.passportBack)}},
  profilePhotos:{approved:image(d.driverProfilePhoto),pending:image(d.pendingDriverProfilePhoto)},
  gallery:(d.driverPhotos||[]).map(p=>({id:p.id,image:image(p.image)})),
  vehicle:{make:d.vehicleMake,model:d.vehicleModel,year:d.vehicleYear,plate:d.vehiclePlate,color:d.vehicleColor,status:d.vehicleDocumentsStatus,message:d.vehicleVerificationMessage,photos:{front:image(d.vehiclePhotosFront),back:image(d.vehiclePhotosBack),left:image(d.vehiclePhotosLeft),right:image(d.vehiclePhotosRight)},registration:{front:image(d.vehicleRegistrationFront),back:image(d.vehicleRegistrationBack)}},
  periodic:{status:d.periodicVehicleVerificationStatus,dueAt:d.periodicVehicleVerificationDueAt,submittedAt:d.periodicVehicleVerificationSubmittedAt,pending:{front:image(d.periodicVehicleFront),back:image(d.periodicVehicleBack),left:image(d.periodicVehicleLeft),right:image(d.periodicVehicleRight),selfie:image(d.periodicFaceSelfie)},approved:{front:image(d.approvedPeriodicVehicleFront),back:image(d.approvedPeriodicVehicleBack),left:image(d.approvedPeriodicVehicleLeft),right:image(d.approvedPeriodicVehicleRight),selfie:image(d.approvedPeriodicFaceSelfie)}}
 }});
}));
app.get('/api/admin/drivers/:id/documents', auth, only('ADMIN'), asyncRoute(async(req,res)=>{
  const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'},select:{
    id:true,name:true,email:true,phone:true,driverFirstNameLatin:true,driverLastNameLatin:true,driverPatronymicLatin:true,
    driverLicenseSeries:true,driverLicenseIssuedAt:true,driverLicenseExpiresAt:true,driverLicenseCategories:true,driverTransmission:true,
    driverDocumentsStatus:true,driverOcrText:true,driverVerificationMessage:true,dateOfBirth:true,passportDocumentType:true,passportIssueDate:true,passportExpiryDate:true,
    passportNumberEncrypted:true,passportIssuedByEncrypted:true,driverLicenseFront:true,driverLicenseBack:true,driverLicenseSelfie:true,
    passportFront:true,passportBack:true,driverProfilePhoto:true,pendingDriverProfilePhoto:true,driverProfilePhotoStatus:true,driverPhotos:{orderBy:{createdAt:'asc'}}
  }});
  if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել'});
  const image=b=>b?'data:image/jpeg;base64,'+decryptPrivate(b).toString('base64'):null;
  const {passportNumberEncrypted,passportIssuedByEncrypted,...safeDriver}=driver;
  res.json({driver:{...safeDriver,passportNumber:decryptPrivate(passportNumberEncrypted)?.toString('utf8')||null,passportIssuedBy:decryptPrivate(passportIssuedByEncrypted)?.toString('utf8')||null,
    driverLicenseFront:image(driver.driverLicenseFront),driverLicenseBack:image(driver.driverLicenseBack),driverLicenseSelfie:image(driver.driverLicenseSelfie),
    passportFront:image(driver.passportFront),passportBack:image(driver.passportBack),driverProfilePhoto:image(driver.driverProfilePhoto),pendingDriverProfilePhoto:image(driver.pendingDriverProfilePhoto),driverProfilePhotoStatus:driver.driverProfilePhotoStatus,gallery:(driver.driverPhotos||[]).map(p=>({id:p.id,image:image(p.image)}))}});
}));

function makeDocumentsPdf(title, pages){
  const objs=[];
  const add=v=>{objs.push(Buffer.isBuffer(v)?v:Buffer.from(v,'binary'));return objs.length};
  const catalog=add(''),pagesId=add(''),fontId=add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'),pageIds=[];
  for(const p of pages){
    const img=decryptPrivate(p.data);
    let iw=1200,ih=800;
    for(let k=2;k<img.length-8;k++){
      if(img[k]===0xff&&[0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(img[k+1])){
        ih=img.readUInt16BE(k+5);iw=img.readUInt16BE(k+7);break;
      }
    }
    const imgId=add(Buffer.concat([
      Buffer.from('<< /Type /XObject /Subtype /Image /Width '+iw+' /Height '+ih+' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length '+img.length+' >>\nstream\n','binary'),
      img,Buffer.from('\nendstream','binary')
    ]));
    const scale=Math.min(520/iw,700/ih),dw=Math.round(iw*scale),dh=Math.round(ih*scale);
    const x=Math.round((595-dw)/2),y=Math.round(430-dh/2);
    const label=String(p.label).replace(/[()\\]/g,'');
    const contentText='BT /F1 14 Tf 40 810 Td ('+label+') Tj ET\nq '+dw+' 0 0 '+dh+' '+x+' '+y+' cm /Im0 Do Q';
    const content=Buffer.from(contentText,'binary');
    const contentId=add(Buffer.concat([
      Buffer.from('<< /Length '+content.length+' >>\nstream\n','binary'),
      content,Buffer.from('\nendstream','binary')
    ]));
    const pageId=add('');pageIds.push(pageId);
    objs[pageId-1]=Buffer.from('<< /Type /Page /Parent '+pagesId+' 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 '+fontId+' 0 R >> /XObject << /Im0 '+imgId+' 0 R >> >> /Contents '+contentId+' 0 R >>');
  }
  objs[catalog-1]=Buffer.from('<< /Type /Catalog /Pages '+pagesId+' 0 R >>');
  objs[pagesId-1]=Buffer.from('<< /Type /Pages /Kids ['+pageIds.map(id=>id+' 0 R').join(' ')+'] /Count '+pageIds.length+' >>');
  let out=Buffer.from('%PDF-1.4\n%âãÏÓ\n','binary'),offsets=[0];
  objs.forEach((o,i)=>{
    offsets.push(out.length);
    out=Buffer.concat([out,Buffer.from((i+1)+' 0 obj\n','binary'),o,Buffer.from('\nendobj\n','binary')]);
  });
  const xref=out.length;
  out=Buffer.concat([out,Buffer.from('xref\n0 '+(objs.length+1)+'\n0000000000 65535 f \n','binary')]);
  for(let i=1;i<offsets.length;i++){
    out=Buffer.concat([out,Buffer.from(String(offsets[i]).padStart(10,'0')+' 00000 n \n','binary')]);
  }
  out=Buffer.concat([out,Buffer.from('trailer\n<< /Size '+(objs.length+1)+' /Root '+catalog+' 0 R >>\nstartxref\n'+xref+'\n%%EOF','binary')]);
  return out;
}

app.get('/api/admin/drivers/:id/documents.pdf',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
  const d=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
  if(!d)return res.status(404).json({error:'Վարորդը չի գտնվել'});
  const pages=[['Driver license front',d.driverLicenseFront],['Driver license back',d.driverLicenseBack],['Driver selfie',d.driverLicenseSelfie],['Passport or ID front',d.passportFront],['Passport or ID back',d.passportBack],['Driver profile photo',d.driverProfilePhoto]].filter(x=>x[1]).map(([label,data])=>({label,data}));
  if(!pages.length)return res.status(404).json({error:'Փաստաթղթեր չկան'});
  const pdf=d.driverDocumentsPdf?decryptPrivate(d.driverDocumentsPdf):makeDocumentsPdf('STAP DRIVER documents',pages);
  res.setHeader('Content-Type','application/pdf');res.setHeader('Content-Disposition','attachment; filename="driver-'+d.id+'-documents.pdf"');res.send(pdf);
}));

app.patch('/api/admin/drivers/:id/verify',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const {verified}=z.object({verified:z.boolean()}).parse(req.body);
 const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել'});
 if(verified&&(!driver.driverLicenseFront||!driver.driverLicenseBack||!driver.driverLicenseSelfie||!driver.passportFront||!driver.passportBack||!driver.driverProfilePhoto||!driver.passportNumberEncrypted||!driver.driverLicenseIssuedAt||!driver.driverLicenseExpiresAt||!driver.driverLicenseCategories.length))return res.status(409).json({error:'Հաստատման համար լրացրեք բոլոր փաստաթղթերը և լուսանկարները։'});
 const verifiedAt=verified?new Date():null;const user=await prisma.user.update({where:{id:driver.id},data:{isVerified:verified,driverDocumentsStatus:verified?'APPROVED':'REJECTED',driverVerifiedAt:verifiedAt,periodicVehicleVerificationDueAt:verified?new Date(verifiedAt.getTime()+DRIVER_PERIODIC_VERIFICATION_MS):null,periodicVehicleVerificationStatus:'NOT_DUE',driverVerificationMessage:verified?'Ադմինը հաստատել է փաստաթղթերը։':'Փաստաթղթերը մերժվել են․ պահանջվում է կրկին ուղարկել։'}});
 res.json({driver:publicUser(user)});
}));


// Admin can inspect and remove individual ratings. Driver score is recomputed by the daily job.
function ratingTrend(ratings){
 const now=Date.now(),day=86400000,cutoff=now-90*day,mid=now-45*day;
 const recent=(ratings||[]).filter(r=>new Date(r.createdAt).getTime()>=cutoff);
 const avg=list=>list.length?Number((list.reduce((sum,r)=>sum+r.score,0)/list.length).toFixed(2)):null;
 const previous=recent.filter(r=>new Date(r.createdAt).getTime()<mid);
 const latest=recent.filter(r=>new Date(r.createdAt).getTime()>=mid);
 const weekly=Array.from({length:13},(_,i)=>{
  const start=now-(13-i)*7*day,end=start+7*day;
  const values=recent.filter(r=>{const t=new Date(r.createdAt).getTime();return t>=start&&t<end});
  return {label:(12-i)+'շ',average:avg(values),count:values.length};
 });
 return {average90:avg(recent),previous45:avg(previous),recent45:avg(latest),change:avg(previous)!==null&&avg(latest)!==null?Number((avg(latest)-avg(previous)).toFixed(2)):null,count90:recent.length,weekly};
}

app.get('/api/admin/ratings/overview',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const users=await prisma.user.findMany({
  where:{role:{in:['DRIVER','CUSTOMER']}},
  select:{id:true,name:true,phone:true,role:true,rating:true,ratingsReceived:{
   orderBy:{createdAt:'desc'},
   include:{fromUser:{select:{name:true,phone:true,role:true}},order:{select:{id:true,createdAt:true}}}
  }}
 });
 res.json({users:users.map(user=>({...user,trend:ratingTrend(user.ratingsReceived)}))});
}));

app.get('/api/admin/drivers/:id/ratings',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել'});
 const ratings=await prisma.rating.findMany({where:{toUserId:driver.id},orderBy:{createdAt:'desc'},include:{fromUser:{select:{name:true,phone:true,role:true}},order:{select:{id:true,createdAt:true}}}});
 res.json({ratings});
}));
app.get('/api/ratings/me/received',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
 const ratings=await prisma.rating.findMany({where:{toUserId:req.user.id},orderBy:{createdAt:'desc'},select:{id:true,score:true,createdAt:true}});
 res.json({ratings});
}));
app.get('/api/ratings/me/trend',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
 const since=new Date(Date.now()-90*86400000);
 const ratings=await prisma.rating.findMany({where:{toUserId:req.user.id,createdAt:{gte:since}},select:{score:true,createdAt:true},orderBy:{createdAt:'asc'}});
 res.json({trend:ratingTrend(ratings)});
}));
app.delete('/api/admin/ratings/:id',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const rating=await prisma.rating.findUnique({where:{id:req.params.id}});
 if(!rating)return res.status(404).json({error:'Գնահատականը չի գտնվել'});
 await prisma.rating.delete({where:{id:rating.id}});
 const result=await prisma.rating.aggregate({where:{toUserId:rating.toUserId},_avg:{score:true}});
 const updatedRating=result._avg.score===null?5:Number(result._avg.score.toFixed(2));
 await prisma.user.update({where:{id:rating.toUserId},data:{rating:updatedRating}});
 res.json({success:true,rating:updatedRating,message:'Գնահատականը հեռացվեց։ Վարորդի վարկանիշը թարմացվեց անմիջապես։'});
}));

app.patch('/api/admin/drivers/:id/documents/review',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const {decision,reason}=z.object({decision:z.enum(['APPROVED','REJECTED','CANCELLED']),reason:z.string().trim().max(500).optional()}).parse(req.body);
 const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել'});
 if(decision==='APPROVED'&&(!driver.driverLicenseFront||!driver.driverLicenseBack||!driver.driverLicenseSelfie||!driver.passportFront||!driver.passportBack))return res.status(409).json({error:'Հաստատման համար լրացրեք բոլոր փաստաթղթերը և լուսանկարները։'});
 if(decision==='REJECTED'&&!reason)return res.status(400).json({error:'Մերժման պատճառը պարտադիր է։'});
 const approved=decision==='APPROVED',status=approved?'APPROVED':decision;
 const note=approved?'Ձեր փաստաթղթերի և լուսանկարների ստուգումը հաջողությամբ անցել է։ Ձեր վարորդի պրոֆիլը հաստատված է։':decision==='REJECTED'?'Փաստաթղթերը մերժվել են։ Պատճառ՝ '+reason+'։ Խնդրում ենք ուղղել և կրկին ուղարկել։':'Ստուգման հարցումը չեղարկվել է ադմինի կողմից։ Կարող եք կրկին ներբեռնել և ուղարկել փաստաթղթերը։';
 const verifiedAt=approved?new Date():null;const user=await prisma.user.update({where:{id:driver.id},data:{driverDocumentsStatus:status,isVerified:approved,driverVerifiedAt:verifiedAt,periodicVehicleVerificationDueAt:approved?new Date(verifiedAt.getTime()+DRIVER_PERIODIC_VERIFICATION_MS):null,periodicVehicleVerificationStatus:'NOT_DUE',driverVerificationMessage:note}});
 await prisma.notification.create({data:{userId:driver.id,title:approved?'Վարորդի պրոֆիլը հաստատված է':decision==='REJECTED'?'Փաստաթղթերը մերժվել են':'Ստուգման հարցումը չեղարկվել է',message:note,type:decision}});
 res.json({driver:publicUser(user),message:approved?'Փաստաթղթերի ստուգումը հաջողությամբ ավարտվեց։':decision==='REJECTED'?'Մերժման ծանուցումն ուղարկվեց վարորդին։':'Չեղարկման ծանուցումն ուղարկվեց վարորդին։'});
}));

app.patch('/api/admin/users/:id/block', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const { blocked } = z.object({ blocked: z.boolean() }).parse(req.body);
  const target = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!target || target.role === 'ADMIN') return res.status(404).json({ error: 'Հաշիվը չի գտնվել' });
  const user = await prisma.user.update({ where: { id: target.id }, data: { isBlocked: blocked } });
  res.json({ user: publicUser(user) });
}));

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const payload = jwt.verify(token, JWT_SECRET, { issuer: 'stap-driver-api' });
    const user = await prisma.user.findUnique({ where: { id: payload.sub } });
    if (!user || user.isBlocked) return next(new Error('Unauthorized'));
    socket.user = publicUser(user);
    next();
  } catch { next(new Error('Unauthorized')); }
});
io.on('connection', socket => {
  socket.join('user:'+socket.user.id);
  if (socket.user.role === 'DRIVER' && socket.user.isVerified && !socket.user.periodicVehicleVerificationRequired) socket.join('drivers');
  socket.on('order:subscribe', async orderId => {
    const order = await prisma.order.findUnique({ where: { id: String(orderId) } });
    if (order && (order.customerId === socket.user.id || order.driverId === socket.user.id)) socket.join('order:' + order.id);
  });
});

app.use((err, req, res, _next) => {
  if (err instanceof z.ZodError) return res.status(400).json({ error: 'Ստուգեք մուտքագրված տվյալները', details: err.issues });
  const requestId=randomBytes(6).toString('hex');
  console.error('[STAP API ERROR]',requestId,req.method,req.originalUrl,err?.code||'',err?.message||err,err?.stack||'');
  res.status(500).json({ error: 'Սերվերի ներքին սխալ', requestId });
});

async function bootstrapAdmin() {
  const email = process.env.ADMIN_EMAIL?.toLowerCase();
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) {
    console.warn('ADMIN_EMAIL/ADMIN_PASSWORD not set; admin account bootstrap skipped.');
    return;
  }
  if (password.length < 14) throw new Error('ADMIN_PASSWORD must contain at least 14 characters.');
  const passwordHash = await bcrypt.hash(password, 12);
  await prisma.user.upsert({
    where: { email },
    update: { role: 'ADMIN', passwordHash, isBlocked: false },
    create: { name: 'STAP Administrator', email, phone: 'not-set', role: 'ADMIN', passwordHash, isVerified: true }
  });
}


// Recalculate all driver ratings daily at 00:01 Yerevan time.
let lastRatingRefreshDay='';
async function refreshDriverRatings(){
 const drivers=await prisma.user.findMany({where:{role:'DRIVER'},select:{id:true}});
 for(const driver of drivers){
  const result=await prisma.rating.aggregate({where:{toUserId:driver.id},_avg:{score:true}});
  const rating=result._avg.score===null?5:Number(result._avg.score.toFixed(2));
  await prisma.user.update({where:{id:driver.id},data:{rating}});
 }
}
setInterval(async()=>{
 try{
  const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Yerevan',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date());
  const value=Object.fromEntries(parts.map(p=>[p.type,p.value]));
  const day=value.year+'-'+value.month+'-'+value.day;
  if(value.hour==='00'&&value.minute==='01'&&lastRatingRefreshDay!==day){
   lastRatingRefreshDay=day;
   await refreshDriverRatings();
   console.log('Daily driver ratings refreshed for',day);
  }
 }catch(error){console.error('Daily rating refresh failed:',error)}
},15000).unref();

async function purgeExpiredOrderInspectionPhotos(){
 const cutoff=new Date(Date.now()-72*60*60*1000);
 const orders=await prisma.order.findMany({where:{status:'COMPLETED',completedAt:{lt:cutoff}},select:{id:true,vehicleInspectionReport:true,vehicleReturnInspection:true}});
 for(const order of orders){
  const strip=report=>{if(!report||typeof report!=='object')return report;const next={...report};for(const key of Object.keys(next)){if(Array.isArray(next[key])&&next[key].some(value=>typeof value==='string'&&value.startsWith('data:image/')))next[key]=[];}return next;};
  const handover=strip(order.vehicleInspectionReport),returned=strip(order.vehicleReturnInspection);
  if(JSON.stringify(handover)!==JSON.stringify(order.vehicleInspectionReport)||JSON.stringify(returned)!==JSON.stringify(order.vehicleReturnInspection))await prisma.order.update({where:{id:order.id},data:{vehicleInspectionReport:handover,vehicleReturnInspection:returned}});
 }
}
purgeExpiredOrderInspectionPhotos().catch(error=>console.error('Initial 72-hour order photo cleanup failed:',error));
setInterval(()=>purgeExpiredOrderInspectionPhotos().catch(error=>console.error('72-hour order photo cleanup failed:',error)),10*60*1000).unref();

server.listen(PORT, '0.0.0.0', () => {
  console.log('STAP DRIVER API listening on ' + PORT);
  bootstrapAdmin().catch(error => {
    console.error('Admin bootstrap failed:', error);
  });
  Promise.allSettled([getYerevanDistrictFeatures(), getYerevanNeighborhoodFeatures()]).then(results => {
    for (const [index, result] of results.entries()) {
      if (result.status === 'fulfilled') {
        console.log(index === 0 ? 'Yerevan district GIS map loaded and persisted.' : 'Yerevan neighborhood GIS map loaded and persisted.');
      } else {
        console.error(index === 0 ? 'Yerevan district GIS import failed:' : 'Yerevan neighborhood GIS import failed:', result.reason?.message || result.reason);
      }
    }
  });
});
