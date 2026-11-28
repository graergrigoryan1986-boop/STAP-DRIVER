ALTER TABLE "User"
  ADD COLUMN "approvedPeriodicVehicleFront" BYTEA,
  ADD COLUMN "approvedPeriodicVehicleBack" BYTEA,
  ADD COLUMN "approvedPeriodicVehicleLeft" BYTEA,
  ADD COLUMN "approvedPeriodicVehicleRight" BYTEA,
  ADD COLUMN "approvedPeriodicFaceSelfie" BYTEA;

UPDATE "User"
SET "periodicVehicleVerificationDueAt" = COALESCE("driverVerifiedAt", "createdAt") + INTERVAL '72 hours'
WHERE "role" = 'DRIVER' AND "isVerified" = TRUE AND "periodicVehicleVerificationDueAt" IS NULL;
