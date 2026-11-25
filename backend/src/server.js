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
app.use(express.json({ limit: '12mb' }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false }));

const publicUser = user => ({
  id: user.id, name: user.name, email: user.email, phone: user.phone,
  role: user.role, isBlocked: user.isBlocked, isVerified: user.isVerified,
  balanceAmd: user.balanceAmd, driverLicense: user.driverLicense,
  driverFirstNameLatin: user.driverFirstNameLatin, driverLastNameLatin: user.driverLastNameLatin,
  driverPatronymicLatin: user.driverPatronymicLatin, driverLicenseSeries: user.driverLicenseSeries,
  driverLicenseExpiresAt: user.driverLicenseExpiresAt, driverLicenseIssuedAt: user.driverLicenseIssuedAt, driverLicenseCategories: user.driverLicenseCategories, driverTransmission: user.driverTransmission, driverDocumentsStatus: user.driverDocumentsStatus, createdAt: user.createdAt
});
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
  const orders = await prisma.order.findMany({ where, orderBy: { createdAt: 'desc' } });
  res.json({ orders });
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
    driverLicenseCategories: z.array(z.string().min(1).max(5)).min(1).max(15),
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
    driverLicenseCategories: z.array(z.string().min(1).max(5)).optional(),
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
  const drivers = await prisma.user.findMany({ where: { role: 'DRIVER' }, orderBy: { createdAt: 'desc' }, select: { id: true, name: true, email: true, phone: true, isBlocked: true, isVerified: true, balanceAmd: true, driverFirstNameLatin: true, driverLastNameLatin: true, driverPatronymicLatin: true, driverLicenseSeries: true, driverLicenseExpiresAt: true, driverLicenseIssuedAt: true, driverLicenseCategories: true, driverTransmission: true, driverDocumentsStatus: true, createdAt: true } });
  res.json({ drivers });
}));

app.post('/api/drivers/documents', auth, only('DRIVER'), asyncRoute(async (req, res) => {
  if (req.user.isVerified) return res.status(403).json({ error: 'Հաստատված պրոֆիլի փաստաթղթերը փոփոխել կարող է միայն ադմինը։' });
  const input = z.object({
    front: z.string().min(100).max(3500000),
    back: z.string().min(100).max(3500000),
    selfie: z.string().min(100).max(3500000),
    ocrText: z.string().max(12000).optional()
  }).parse(req.body);
  const decode = value => {
    const raw = value.replace(/^data:image\/(jpeg|jpg|png|webp);base64,/i, '');
    if (!/^[A-Za-z0-9+/=]+$/.test(raw)) throw new Error('Նկարի ձևաչափը սխալ է');
    const buffer = Buffer.from(raw, 'base64');
    if (!buffer.length || buffer.length > 2500000) throw new Error('Յուրաքանչյուր նկարը պետք է լինի առավելագույնը 2.5 ՄԲ');
    return buffer;
  };
  const [front, back, selfie] = [decode(input.front), decode(input.back), decode(input.selfie)];
  const user = await prisma.user.update({ where: { id: req.user.id }, data: {
    driverLicenseFront: front, driverLicenseBack: back, driverLicenseSelfie: selfie,
    driverDocumentsStatus: 'PENDING', driverOcrText: input.ocrText || null, isVerified: false
  }});
  res.json({ success: true, driverDocumentsStatus: user.driverDocumentsStatus, message: 'Փաստաթղթերն ուղարկվեցին ադմինի ֆոտովերահսկմանը։' });
}));

app.get('/api/admin/drivers/:id/documents', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const driver = await prisma.user.findFirst({ where: { id: req.params.id, role: 'DRIVER' }, select: {
    id: true, name: true, driverFirstNameLatin: true, driverLastNameLatin: true, driverPatronymicLatin: true,
    driverLicenseSeries: true, driverLicenseIssuedAt: true, driverLicenseExpiresAt: true,
    driverLicenseCategories: true, driverTransmission: true, driverDocumentsStatus: true, driverOcrText: true,
    driverLicenseFront: true, driverLicenseBack: true, driverLicenseSelfie: true
  }});
  if (!driver) return res.status(404).json({ error: 'Վարորդը չի գտնվել' });
  const encode = value => value ? 'data:image/jpeg;base64,'+Buffer.from(value).toString('base64') : null;
  res.json({ driver: { ...driver, driverLicenseFront: encode(driver.driverLicenseFront), driverLicenseBack: encode(driver.driverLicenseBack), driverLicenseSelfie: encode(driver.driverLicenseSelfie) } });
}));

app.patch('/api/admin/drivers/:id/verify', auth, only('ADMIN'), asyncRoute(async (req, res) => {
  const { verified } = z.object({ verified: z.boolean() }).parse(req.body);
  const driver = await prisma.user.findFirst({ where: { id: req.params.id, role: 'DRIVER' } });
  if (!driver) return res.status(404).json({ error: 'Վարորդը չի գտնվել' });
  if (verified && (!driver.driverLicenseFront || !driver.driverLicenseBack || !driver.driverLicenseSelfie || driver.driverDocumentsStatus !== 'PENDING' || !driver.driverLicenseIssuedAt || !driver.driverLicenseExpiresAt || !driver.driverLicenseCategories.length || !driver.driverFirstNameLatin || !driver.driverLastNameLatin)) {
    return res.status(409).json({ error: 'Հաստատման համար անհրաժեշտ են երեք լուսանկար, տրման ամսաթիվ և վարորդական կարգեր։' });
  }
  const user = await prisma.user.update({ where: { id: driver.id }, data: { isVerified: verified, driverDocumentsStatus: verified ? 'APPROVED' : driver.driverDocumentsStatus } });
  res.json({ driver: publicUser(user) });
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
