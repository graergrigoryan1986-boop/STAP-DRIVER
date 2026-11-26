ALTER TABLE "User" ADD COLUMN "pendingDriverProfilePhoto" BYTEA, ADD COLUMN "driverProfilePhotoStatus" TEXT NOT NULL DEFAULT 'NONE';
