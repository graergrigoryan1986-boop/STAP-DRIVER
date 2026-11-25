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

app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", 'https://cdn.jsdelivr.net', "'wasm-unsafe-eval'"], workerSrc: ["'self'", 'blob:'], connectSrc: ["'self'", 'https://cdn.jsdelivr.net', 'https://tessdata.projectnaptha.com'], imgSrc: ["'self'", 'data:', 'blob:'], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'] } } }));
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
const publicUser = user => ({
  id: user.id, name: user.name, email: user.email, phone: user.phone,
  role: user.role, isBlocked: user.isBlocked, isVerified: user.isVerified,
  balanceAmd: user.balanceAmd, driverLicense: user.driverLicense,
  driverFirstNameLatin: user.driverFirstNameLatin, driverLastNameLatin: user.driverLastNameLatin,
  driverPatronymicLatin: user.driverPatronymicLatin, driverLicenseSeries: user.driverLicenseSeries,
  driverLicenseExpiresAt: user.driverLicenseExpiresAt, driverLicenseIssuedAt: user.driverLicenseIssuedAt, driverLicenseCategories: user.driverLicenseCategories, driverTransmission: user.driverTransmission, driverDocumentsStatus: user.driverDocumentsStatus, driverVerifiedAt: user.driverVerifiedAt, driverVerificationMessage: user.driverVerificationMessage, createdAt: user.createdAt
});
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

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'STAP DRIVER API' }));

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
    driverLicenseIssuedAt: z.iso.date().optional()
  }).parse(req.body);
  if (input.role === 'DRIVER' && !input.driverLicense) return res.status(400).json({ error: 'Վարորդական իրավունքի տվյալները պարտադիր են' });
  const exists = await prisma.user.findUnique({ where: { email: input.email } });
  if (exists) return res.status(409).json({ error: 'Այս էլ․ փոստն արդեն գրանցված է' });
  const passwordHash = await bcrypt.hash(input.password, 12);
  const user = await prisma.user.create({ data: {
    name: input.name, email: input.email, phone: input.phone, passwordHash,
    role: input.role, driverLicense: input.driverLicense || null,
    driverFirstNameLatin: input.driverFirstNameLatin || null, driverLastNameLatin: input.driverLastNameLatin || null,
    driverPatronymicLatin: input.driverPatronymicLatin || null, driverLicenseSeries: input.driverLicenseSeries || null,
    driverLicenseExpiresAt: input.driverLicenseExpiresAt ? new Date(input.driverLicenseExpiresAt+'T00:00:00.000Z') : null,
    driverLicenseIssuedAt: input.driverLicenseIssuedAt ? new Date(input.driverLicenseIssuedAt+'T00:00:00.000Z') : null
  }});
  res.status(201).json({ token: signToken(user), user: publicUser(user) });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const input = z.object({ email: z.email().transform(v => v.toLowerCase()), password: z.string().min(1).max(128) }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email: input.email } });
  if (!user || !(await bcrypt.compare(input.password, user.passwordHash))) return res.status(401).json({ error: 'Էլ․ փոստը կամ գաղտնաբառը սխալ է' });
  if (user.isBlocked) return res.status(403).json({ error: 'Հաշիվն արգելափակված է' });
  res.json({ token: signToken(user), user: publicUser(user) });
}));

app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.patch('/api/customer/profile', auth, only('CUSTOMER'), asyncRoute(async (req, res) => {
  const { driverLicenseIssuedAt } = z.object({ driverLicenseIssuedAt: z.iso.date().or(z.literal('')) }).parse(req.body);
  const user = await prisma.user.update({ where: { id: req.user.id }, data: {
    driverLicenseIssuedAt: driverLicenseIssuedAt ? new Date(driverLicenseIssuedAt+'T00:00:00.000Z') : null
  }});
  res.json({ user: publicUser(user), message: 'Վարորդական ստաժի տվյալը պահպանվեց։' });
}));

app.post('/api/orders', auth, only('CUSTOMER'), asyncRoute(async (req, res) => {
  const input = z.object({
    pickupAddress: z.string().trim().min(3).max(300),
    destinationAddress: z.string().trim().min(3).max(300),
    pickupLat: z.number().min(-90).max(90).optional(),
    pickupLng: z.number().min(-180).max(180).optional(),
    destinationLat: z.number().min(-90).max(90).optional(),
    destinationLng: z.number().min(-180).max(180).optional(),
    fareAmd: z.number().int().min(1000).max(1000000),
    requiredLicenseCategory: z.string().trim().min(1).max(5).default('B'),
    transmissionType: z.enum(['AUTOMATIC','MANUAL']).default('AUTOMATIC'),
    note: z.string().max(1000).optional()
  }).parse(req.body);
  const order = await prisma.order.create({ data: { ...input, customerId: req.user.id } });
  io.to('drivers').emit('order:new', { id: order.id, pickupAddress: order.pickupAddress, destinationAddress: order.destinationAddress, fareAmd: order.fareAmd, createdAt: order.createdAt });
  res.status(201).json({ order });
}));

app.get('/api/orders/open', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const orders = await prisma.order.findMany({ where: { status: 'OPEN', skippedBy: { none: { driverId: req.user.id } } }, orderBy: { createdAt: 'asc' } });
  const categories = req.user.driverLicenseCategories || [];
  const ordersForDriver = orders.filter(order =>
    categories.includes(order.requiredLicenseCategory) &&
    (order.transmissionType !== 'MANUAL' || req.user.driverTransmission === 'MANUAL')
  );
  res.json({ orders: ordersForDriver });
}));

app.get('/api/orders/mine', auth, asyncRoute(async (req, res) => {
  if (req.user.role === 'DRIVER') {
    const [assigned, skipped] = await Promise.all([
      prisma.order.findMany({ where: { driverId: req.user.id }, orderBy: { createdAt: 'desc' } }),
      prisma.skippedOrder.findMany({ where: { driverId: req.user.id }, include: { order: true }, orderBy: { createdAt: 'desc' } })
    ]);
    const orders = [...assigned, ...skipped.map(x => ({ ...x.order, status: 'SKIPPED', skippedAt: x.createdAt }))].sort((a,b) => new Date(b.createdAt)-new Date(a.createdAt));
    return res.json({ orders });
  }
  const where = req.user.role === 'CUSTOMER' ? { customerId: req.user.id } : {};
  const orders = await prisma.order.findMany({
    where, orderBy: { createdAt: 'desc' },
    include: req.user.role === 'CUSTOMER' ? { driver: { select: {
      id:true,name:true,rating:true,driverFirstNameLatin:true,driverLastNameLatin:true,
      driverLicenseIssuedAt:true,driverLicenseCategories:true,driverTransmission:true,dateOfBirth:true,
      isVerified:true,driverProfilePhoto:true
    }}} : undefined
  });
  const safeOrders = req.user.role === 'CUSTOMER' ? orders.map(o => ({
    ...o, driver: o.driver ? {
      id:o.driver.id,name:o.driver.name,rating:o.driver.rating,age:o.driver.dateOfBirth?Math.max(0,new Date().getUTCFullYear()-new Date(o.driver.dateOfBirth).getUTCFullYear()-((new Date().getUTCMonth()<new Date(o.driver.dateOfBirth).getUTCMonth()||(new Date().getUTCMonth()===new Date(o.driver.dateOfBirth).getUTCMonth()&&new Date().getUTCDate()<new Date(o.driver.dateOfBirth).getUTCDate()))?1:0)):null,
      driverFirstNameLatin:o.driver.driverFirstNameLatin,driverLastNameLatin:o.driver.driverLastNameLatin,
      driverLicenseIssuedAt:o.driver.driverLicenseIssuedAt,driverLicenseCategories:o.driver.driverLicenseCategories,
      driverTransmission:o.driver.driverTransmission,isVerified:o.driver.isVerified,
      profilePhoto:o.driver.driverProfilePhoto ? 'data:image/jpeg;base64,'+decryptPrivate(o.driver.driverProfilePhoto).toString('base64') : null
    } : null
  })) : orders;
  res.json({ orders: safeOrders });
}));

app.post('/api/orders/:id/skip', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const order = await prisma.order.findFirst({ where: { id: req.params.id, status: 'OPEN', driverId: null } });
  if (!order) return res.status(404).json({ error: 'Բաց պատվերը չի գտնվել' });
  await prisma.skippedOrder.upsert({
    where: { orderId_driverId: { orderId: order.id, driverId: req.user.id } },
    update: {},
    create: { orderId: order.id, driverId: req.user.id }
  });
  res.json({ success: true, message: 'Պատվերը նշվեց որպես բաց թողնված։' });
}));

app.post('/api/orders/:id/cancel', auth, only('CUSTOMER'), asyncRoute(async (req, res) => {
  const result = await prisma.order.updateMany({
    where: { id: req.params.id, customerId: req.user.id, status: { in: ['OPEN', 'ACCEPTED'] } },
    data: { status: 'CANCELLED' }
  });
  if (!result.count) return res.status(409).json({ error: 'Պատվերը հնարավոր չէ չեղարկել այս կարգավիճակում' });
  res.json({ success: true, message: 'Պատվերը չեղարկվեց։' });
}));

app.post('/api/orders/:id/accept', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const requestedOrder = await prisma.order.findFirst({ where: { id: req.params.id, status: 'OPEN', driverId: null } });
  if (!requestedOrder) return res.status(409).json({ error: 'Պատվերն արդեն ընդունվել է կամ հասանելի չէ' });
  if (!(req.user.driverLicenseCategories || []).includes(requestedOrder.requiredLicenseCategory) ||
      (requestedOrder.transmissionType === 'MANUAL' && req.user.driverTransmission !== 'MANUAL')) {
    return res.status(403).json({ error: 'Այս պատվերի մեքենայի կարգը կամ փոխանցման տուփը ձեր իրավասության մեջ չէ։' });
  }
  const result = await prisma.order.updateMany({
    where: { id: req.params.id, status: 'OPEN', driverId: null },
    data: { status: 'ACCEPTED', driverId: req.user.id, acceptedAt: new Date() }
  });
  if (!result.count) return res.status(409).json({ error: 'Պատվերն արդեն ընդունվել է կամ հասանելի չէ' });
  const order = await prisma.order.findUnique({ where: { id: req.params.id } });
  io.emit('order:accepted', { id: order.id, driverId: req.user.id, status: order.status });
  res.json({ order });
}));

app.post('/api/orders/:id/start', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const result = await prisma.order.updateMany({ where: { id: req.params.id, driverId: req.user.id, status: 'ACCEPTED' }, data: { status: 'IN_PROGRESS' } });
  if (!result.count) return res.status(409).json({ error: 'Պատվերի կարգավիճակը հնարավոր չէ փոխել' });
  res.json({ order: await prisma.order.findUnique({ where: { id: req.params.id } }) });
}));

app.post('/api/orders/:id/complete', auth, only('DRIVER'), verifiedDriver, asyncRoute(async (req, res) => {
  const result = await prisma.$transaction(async tx => {
    const order = await tx.order.findFirst({ where: { id: req.params.id, driverId: req.user.id, status: 'IN_PROGRESS' } });
    if (!order) return null;
    const commissionAmd = Math.round(order.fareAmd * 0.25);
    const driverEarningAmd = order.fareAmd - commissionAmd;
    await tx.order.update({ where: { id: order.id }, data: { status: 'COMPLETED', commissionRate: 25, commissionAmd, driverEarningAmd, completedAt: new Date() } });
    await tx.user.update({ where: { id: req.user.id }, data: { balanceAmd: { increment: driverEarningAmd } } });
    await tx.walletTransaction.create({ data: { userId: req.user.id, amountAmd: driverEarningAmd, type: 'ORDER_EARNING', description: 'Վարորդի եկամուտ՝ ավարտված պատվերից', orderId: order.id } });
    return { commissionAmd, driverEarningAmd, fareAmd: order.fareAmd };
  });
  if (!result) return res.status(409).json({ error: 'Պատվերը հնարավոր չէ ավարտել' });
  io.emit('order:completed', { id: req.params.id });
  res.json({ success: true, settlement: result });
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
    driverFirstNameLatin: z.string().trim().min(2).max(80),
    driverLastNameLatin: z.string().trim().min(2).max(80),
    driverPatronymicLatin: z.string().trim().max(80).optional().or(z.literal('')),
    driverLicenseSeries: z.string().trim().min(3).max(40),
    driverLicenseExpiresAt: z.iso.date(),
    driverLicenseIssuedAt: z.iso.date().optional(),
    driverTransmission: z.enum(['AUTOMATIC','MANUAL']).optional()
  }).parse(req.body);
  const driver = await prisma.user.findFirst({ where: { id: req.params.id, role: 'DRIVER' } });
  if (!driver) return res.status(404).json({ error: 'Վարորդը չի գտնվել' });
  const user = await prisma.user.update({ where: { id: driver.id }, data: {
    ...input, driverLicenseExpiresAt: new Date(input.driverLicenseExpiresAt+'T00:00:00.000Z'), ...(input.driverLicenseIssuedAt ? { driverLicenseIssuedAt: new Date(input.driverLicenseIssuedAt+'T00:00:00.000Z') } : {})
  }});
  res.json({ user: publicUser(user), message: 'Վարորդական տվյալները թարմացվեցին ադմինի կողմից։' });
}));

app.get('/api/drivers/wallet', auth, only('DRIVER'), asyncRoute(async (req, res) => {
  const transactions = await prisma.walletTransaction.findMany({
    where: { userId: req.user.id }, orderBy: { createdAt: 'desc' }, take: 100
  });
  res.json({ transactions });
}));

app.get('/api/admin/drivers/:id/transactions', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const transactions = await prisma.walletTransaction.findMany({
    where: { userId: req.params.id }, orderBy: { createdAt: 'desc' }, take: 100
  });
  res.json({ transactions });
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
    const changed = await tx.user.updateMany({
      where: { id: driver.id, balanceAmd: { gte: amountAmd } },
      data: { balanceAmd: { decrement: amountAmd } }
    });
    if (!changed.count) return null;
    const user = await tx.user.findUnique({ where: { id: driver.id } });
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
  if (!result) return res.status(409).json({ error: 'Վարորդի հաշվեկշռում բավարար գումար չկա։' });
  res.json({ driver: publicUser(result), message: 'Գումարը ելքագրվեց վարորդի հաշվեկշռից։' });
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
  const drivers = await prisma.user.findMany({ where: { role: 'DRIVER' }, orderBy: { createdAt: 'desc' }, select: { id: true, name: true, email: true, phone: true, isBlocked: true, isVerified: true, balanceAmd: true, driverFirstNameLatin: true, driverLastNameLatin: true, driverPatronymicLatin: true, driverLicenseSeries: true, driverLicenseExpiresAt: true, driverLicenseIssuedAt: true, driverLicenseCategories: true, driverTransmission: true, driverDocumentsStatus: true, driverVerificationMessage: true, driverVerifiedAt: true, createdAt: true } });
  res.json({ drivers });
}));

app.post('/api/drivers/documents', auth, only('DRIVER'), asyncRoute(async (req, res) => {
  if (req.user.isVerified) return res.status(403).json({ error: 'Հաստատված փաստաթղթերը փոփոխել կարող է միայն ադմինը։' });
  const input=z.object({
    front:z.string().min(100).max(3500000),back:z.string().min(100).max(3500000),selfie:z.string().min(100).max(3500000),
    passportDocumentType:z.enum(['PASSPORT','ID_CARD']),
    passportFront:z.string().min(100).max(3500000),passportBack:z.string().min(100).max(3500000),
    ocrText:z.string().max(24000),passportOcrText:z.string().max(24000)
  }).parse(req.body);
  const decode=value=>{
    const match=value.match(/^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/i);
    if(!match)throw new Error('Նկարը պետք է լինի JPG/JPEG։');
    const buffer=Buffer.from(match[1],'base64');
    if(buffer[0]!==0xff||buffer[1]!==0xd8||!buffer.length||buffer.length>2500000)throw new Error('Յուրաքանչյուր լուսանկարը պետք է լինի վավեր JPEG և առավելագույնը 2.5 ՄԲ։');
    return encryptPrivate(buffer);
  };
  const docs={front:decode(input.front),back:decode(input.back),selfie:decode(input.selfie),passportFront:decode(input.passportFront),passportBack:decode(input.passportBack)};
  const identity=parseMrzIdentity(input.passportOcrText);
  const clean=value=>String(value||'').toLocaleUpperCase().normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^A-ZԱ-Ֆ]/g,'');
  const licenseText=String(input.ocrText||''),licenseClean=clean(licenseText);
  const surname=clean(identity?.surname),firstName=clean(identity?.firstName),licenseLatin=clean(transliterateArmenian(licenseText));
  const namesMatch=Boolean(surname.length>=3&&firstName.length>=2&&(licenseClean.includes(surname)&&licenseClean.includes(firstName)||licenseLatin.includes(surname)&&licenseLatin.includes(firstName)));
  const licenseBackText=licenseText.split('ՎԱՐՈՐԴԱԿԱՆ ՀԵՏԵՎ')[1]||'';
  const detectedLicenseCategories=extractLicenseCategories(licenseBackText);
  const licenseBirthDate=labelledDate(licenseText,[/\b3\b/i,/date of birth/i,/birth date/i,/ծննդյան ամսաթիվ/i]);
  const issueDate=labelledDate(licenseText,[/\b4a\b/i,/date of issue/i,/issue date/i,/issued/i,/տրման ամսաթիվ/i,/տրամադրման ամսաթիվ/i]);
  const licenseExpiry=labelledDate(licenseText,[/\b4b\b/i,/date of expiry/i,/expiry date/i,/valid until/i,/վավեր է մինչև/i,/գործողության ավարտ/i]);
  const now=new Date(),birthDate=identity?.birthDate||null,passportExpiry=identity?.expiryDate||null;
  const age=birthDate?now.getUTCFullYear()-birthDate.getUTCFullYear()-((now.getUTCMonth()<birthDate.getUTCMonth()||(now.getUTCMonth()===birthDate.getUTCMonth()&&now.getUTCDate()<birthDate.getUTCDate()))?1:0):null;
  const expired=Boolean((birthDate&&birthDate>now)||(age!==null&&age<18)||(passportExpiry&&passportExpiry<=now)||(licenseExpiry&&licenseExpiry<=now)||(issueDate&&issueDate>now));
  const datesMatch=Boolean(birthDate&&licenseBirthDate&&birthDate.getTime()===licenseBirthDate.getTime());
  const allReadable=Boolean(identity&&birthDate&&passportExpiry&&licenseBirthDate&&issueDate&&licenseExpiry&&datesMatch&&namesMatch&&detectedLicenseCategories.length>0);
  const autoPassed=allReadable&&!expired,status=autoPassed?'AUTO_APPROVED':'REJECTED';
  const passportNumber=identity?.passportNumber||'';
  const user=await prisma.user.update({where:{id:req.user.id},data:{
    driverLicenseFront:docs.front,driverLicenseBack:docs.back,driverLicenseSelfie:docs.selfie,
    passportDocumentType:input.passportDocumentType,passportNumberEncrypted:passportNumber?encryptPrivate(passportNumber):null,
    passportIssuedByEncrypted:null,dateOfBirth:birthDate,passportIssueDate:null,passportExpiryDate:passportExpiry,
    passportFront:docs.passportFront,passportBack:docs.passportBack,driverProfilePhoto:docs.selfie,
    driverFirstNameLatin:identity?.firstName||null,driverLastNameLatin:identity?.surname||null,driverPatronymicLatin:null,
    driverLicenseCategories:detectedLicenseCategories,driverLicenseIssuedAt:issueDate,driverLicenseExpiresAt:licenseExpiry,
    driverOcrText:licenseText,driverDocumentsStatus:status,isVerified:autoPassed,driverVerifiedAt:autoPassed?new Date():null,
    driverVerificationMessage:autoPassed?'Փաստաթղթերի OCR տվյալները համընկել են։ Վարորդը հաստատվեց։':expired?'Փաստաթղթի ժամկետը լրացած է կամ տարիքը չի համապատասխանում։ Խնդրում ենք ուղարկել գործող փաստաթղթերի նոր լուսանկարներ։':'Տվյալները չեն համընկել կամ փաստաթղթերը հստակ չեն ընթերցվել։ Ստուգեք լուսանկարների որակը և կրկին ուղարկեք բոլոր լուսանկարները։',
    driverDocumentsPdf:encryptPrivate(makeDocumentsPdf('STAP DRIVER identity documents',[
      ['Driver license front',docs.front],['Driver license back',docs.back],['Driver selfie',docs.selfie],
      [input.passportDocumentType==='PASSPORT'?'Passport photo page':'ID card front',docs.passportFront],
      [input.passportDocumentType==='PASSPORT'?'Passport registration page':'ID card back',docs.passportBack]
    ].map(([label,data])=>({label,data}))))
  }});
  res.json({success:true,user:publicUser(user),message:autoPassed?'Փաստաթղթերի տվյալները համընկել են․ վարորդը ավտոմատ հաստատվեց։':'Նույնականացումը չհաստատվեց։ Տվյալները չեն համընկել կամ լուսանկարները հստակ չեն ընթերցվել։ Խնդրում ենք կրկին ուղարկել բոլոր լուսանկարները։'});
}));

app.post('/api/drivers/profile-photo', auth, only('DRIVER'), asyncRoute(async(req,res)=>{
  if(req.user.isVerified)return res.status(403).json({error:'Հաստատված պրոֆիլի լուսանկարը փոխել կարող է միայն ադմինը։'});
  const {photo}=z.object({photo:z.string().min(100).max(3500000)}).parse(req.body);
  const match=photo.match(/^data:image\/(jpeg|jpg|png|webp);base64,([A-Za-z0-9+/=]+)$/i);
  if(!match)return res.status(400).json({error:'Ընտրեք JPG, PNG կամ WEBP լուսանկար։'});
  const data=Buffer.from(match[2],'base64');if(!data.length||data.length>2500000)return res.status(400).json({error:'Լուսանկարը պետք է լինի առավելագույնը 2.5 ՄԲ։'});
  await prisma.user.update({where:{id:req.user.id},data:{driverProfilePhoto:encryptPrivate(data)}});
  res.json({success:true,message:'Պրոֆիլի լուսանկարը պահպանվեց։'});
}));

app.get('/api/drivers/profile-photo',auth,only('DRIVER'),asyncRoute(async(req,res)=>{
  if(!req.user.driverProfilePhoto)return res.json({photo:null});
  res.json({photo:'data:image/jpeg;base64,'+decryptPrivate(req.user.driverProfilePhoto).toString('base64')});
}));

app.get('/api/admin/drivers/:id/documents', auth, only('ADMIN'), asyncRoute(async(req,res)=>{
  const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'},select:{
    id:true,name:true,email:true,phone:true,driverFirstNameLatin:true,driverLastNameLatin:true,driverPatronymicLatin:true,
    driverLicenseSeries:true,driverLicenseIssuedAt:true,driverLicenseExpiresAt:true,driverLicenseCategories:true,driverTransmission:true,
    driverDocumentsStatus:true,driverOcrText:true,driverVerificationMessage:true,dateOfBirth:true,passportDocumentType:true,passportIssueDate:true,passportExpiryDate:true,
    passportNumberEncrypted:true,passportIssuedByEncrypted:true,driverLicenseFront:true,driverLicenseBack:true,driverLicenseSelfie:true,
    passportFront:true,passportBack:true,driverProfilePhoto:true
  }});
  if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել'});
  const image=b=>b?'data:image/jpeg;base64,'+decryptPrivate(b).toString('base64'):null;
  const {passportNumberEncrypted,passportIssuedByEncrypted,...safeDriver}=driver;
  res.json({driver:{...safeDriver,passportNumber:decryptPrivate(passportNumberEncrypted)?.toString('utf8')||null,passportIssuedBy:decryptPrivate(passportIssuedByEncrypted)?.toString('utf8')||null,
    driverLicenseFront:image(driver.driverLicenseFront),driverLicenseBack:image(driver.driverLicenseBack),driverLicenseSelfie:image(driver.driverLicenseSelfie),
    passportFront:image(driver.passportFront),passportBack:image(driver.passportBack),driverProfilePhoto:image(driver.driverProfilePhoto)}});
}));

function makeDocumentsPdf(title, pages){
  const objs=[];const add=v=>{objs.push(Buffer.isBuffer(v)?v:Buffer.from(v,'binary'));return objs.length};
  const catalog=add(''),pagesId=add(''),fontId=add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'),pageIds=[];
  for(const p of pages){
    const img=decryptPrivate(p.data);let iw=1200,ih=800;for(let k=2;k<img.length-8;k++){if(img[k]===0xff&&[0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(img[k+1])){ih=img.readUInt16BE(k+5);iw=img.readUInt16BE(k+7);break}}const imgId=add(Buffer.concat([Buffer.from('<< /Type /XObject /Subtype /Image /Width '+iw+' /Height '+ih+' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length '+img.length+' >>\nstream\n'),img,Buffer.from('\nendstream')]));
    const scale=Math.min(520/iw,700/ih),dw=Math.round(iw*scale),dh=Math.round(ih*scale),x=Math.round((595-dw)/2),y=Math.round(430-dh/2);const contentText='BT /F1 14 Tf 40 810 Td ('+String(p.label).replace(/[()\\]/g,'')+') Tj ET\nq '+dw+' 0 0 '+dh+' '+x+' '+y+' cm /Im0 Do Q';
    const content=Buffer.from(contentText,'binary'),contentId=add(Buffer.concat([Buffer.from('<< /Length '+content.length+' >>\nstream\n'),content,Buffer.from('\nendstream')]));
    const pageId=add('');pageIds.push(pageId);
    objs[pageId-1]=Buffer.from('<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 '+fontId+' 0 R >> /XObject << /Im0 '+imgId+' 0 R >> >> /Contents '+contentId+' 0 R >>');
  }
  objs[catalog-1]=Buffer.from('<< /Type /Catalog /Pages '+pagesId+' 0 R >>');
  objs[pagesId-1]=Buffer.from('<< /Type /Pages /Kids ['+pageIds.map(id=>id+' 0 R').join(' ')+'] /Count '+pageIds.length+' >>');
  let out=Buffer.from('%PDF-1.4\n%âãÏÓ\n','binary'),offsets=[0];
  objs.forEach((o,i)=>{offsets.push(out.length);out=Buffer.concat([out,Buffer.from((i+1)+' 0 obj\n'),o,Buffer.from('\nendobj\n')])});
  const xref=out.length;out=Buffer.concat([out,Buffer.from('xref\n0 '+(objs.length+1)+'\n0000000000 65535 f \n')]);
  for(let i=1;i<offsets.length;i++)out=Buffer.concat([out,Buffer.from(String(offsets[i]).padStart(10,'0')+' 00000 n \n')]);
  out=Buffer.concat([out,Buffer.from('trailer\n<< /Size '+(objs.length+1)+' /Root '+catalog+' 0 R >>\nstartxref\n'+xref+'\n%%EOF')]);return out;
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
 const user=await prisma.user.update({where:{id:driver.id},data:{isVerified:verified,driverDocumentsStatus:verified?'APPROVED':'REJECTED',driverVerifiedAt:verified?new Date():null,driverVerificationMessage:verified?'Ադմինը հաստատել է փաստաթղթերը։':'Փաստաթղթերը մերժվել են․ պահանջվում է կրկին ուղարկել։'}});
 res.json({driver:publicUser(user)});
}));

app.patch('/api/admin/drivers/:id/documents/review',auth,only('ADMIN'),asyncRoute(async(req,res)=>{
 const {approved}=z.object({approved:z.boolean()}).parse(req.body);
 const driver=await prisma.user.findFirst({where:{id:req.params.id,role:'DRIVER'}});
 if(!driver)return res.status(404).json({error:'Վարորդը չի գտնվել'});
 if(approved&&(!driver.driverLicenseFront||!driver.driverLicenseBack||!driver.driverLicenseSelfie||!driver.passportFront||!driver.passportBack))return res.status(409).json({error:'Բոլոր փաստաթղթերը պարտադիր են։'});
 const user=await prisma.user.update({where:{id:driver.id},data:{driverDocumentsStatus:approved?'APPROVED':'REJECTED',isVerified:approved,driverVerifiedAt:approved?new Date():null,driverVerificationMessage:approved?'Փաստաթղթերը հաստատվեցին։':'Փաստաթղթերը մերժվեցին․ խնդրում ենք ուղղել և կրկին ուղարկել։'}});
 res.json({driver:publicUser(user),message:approved?'Փաստաթղթերը հաստատվեցին։':'Փաստաթղթերը մերժվեցին։ Վարորդին կպահանջվի կրկին ուղարկել։'});
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
  if (socket.user.role === 'DRIVER' && socket.user.isVerified) socket.join('drivers');
  socket.on('order:subscribe', async orderId => {
    const order = await prisma.order.findUnique({ where: { id: String(orderId) } });
    if (order && (order.customerId === socket.user.id || order.driverId === socket.user.id)) socket.join('order:' + order.id);
  });
});

app.use((err, _req, res, _next) => {
  if (err instanceof z.ZodError) return res.status(400).json({ error: 'Ստուգեք մուտքագրված տվյալները', details: err.issues });
  console.error(err);
  res.status(500).json({ error: 'Սերվերի ներքին սխալ' });
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

server.listen(PORT, '0.0.0.0', () => {
  console.log('STAP DRIVER API listening on ' + PORT);
  bootstrapAdmin().catch(error => {
    console.error('Admin bootstrap failed:', error);
  });
});
