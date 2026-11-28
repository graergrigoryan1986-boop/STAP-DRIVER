ALTER TABLE "User"
  ADD COLUMN "periodicVehicleVerificationStatus" TEXT NOT NULL DEFAULT 'NOT_DUE',
  ADD COLUMN "periodicVehicleVerificationDueAt" TIMESTAMP(3),
  ADD COLUMN "periodicVehicleVerificationSubmittedAt" TIMESTAMP(3),
  ADD COLUMN "periodicVehicleFront" BYTEA,
  ADD COLUMN "periodicVehicleBack" BYTEA,
  ADD COLUMN "periodicVehicleLeft" BYTEA,
  ADD COLUMN "periodicVehicleRight" BYTEA,
  ADD COLUMN "periodicFaceSelfie" BYTEA;

UPDATE "User"
SET "periodicVehicleVerificationDueAt" = "driverVerifiedAt" + INTERVAL '72 hours'
WHERE "role" = 'DRIVER' AND "isVerified" = TRUE AND "driverVerifiedAt" IS NOT NULL;
