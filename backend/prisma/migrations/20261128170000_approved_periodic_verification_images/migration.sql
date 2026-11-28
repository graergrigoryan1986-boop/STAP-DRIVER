ALTER TABLE "User"
  ADD COLUMN "approvedPeriodicVehicleFront" BYTEA,
  ADD COLUMN "approvedPeriodicVehicleBack" BYTEA,
  ADD COLUMN "approvedPeriodicVehicleLeft" BYTEA,
  ADD COLUMN "approvedPeriodicVehicleRight" BYTEA,
  ADD COLUMN "approvedPeriodicFaceSelfie" BYTEA;
