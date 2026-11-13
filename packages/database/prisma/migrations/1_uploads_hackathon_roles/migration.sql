-- CreateTable
CREATE TABLE "upload" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "userId" TEXT,
    "storageName" TEXT NOT NULL,
    "originalName" TEXT NOT NULL,
    "sanitizedName" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "sha256" TEXT NOT NULL,
    "storagePath" TEXT NOT NULL,
    "metadata" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "upload_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "hackathon_submission" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "userEmail" TEXT NOT NULL,
    "plan" TEXT NOT NULL,
    "projectName" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "sourceCodeUrl" TEXT NOT NULL,
    "sourceCodeType" TEXT NOT NULL,
    "apiUsageEndpoints" JSONB NOT NULL,
    "demoUrl" TEXT,
    "videoUrl" TEXT,
    "confirmedTerms" BOOLEAN NOT NULL,
    "score" INTEGER,
    "status" TEXT NOT NULL DEFAULT 'SUBMITTED',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "hackathon_submission_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "upload_organizationId_createdAt_idx" ON "upload"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "hackathon_submission_organizationId_idx" ON "hackathon_submission"("organizationId");

-- CreateIndex
CREATE INDEX "hackathon_submission_createdAt_idx" ON "hackathon_submission"("createdAt");

-- AddForeignKey
ALTER TABLE "upload" ADD CONSTRAINT "upload_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;


-- Normalize role casing: the database stores lowercase roles (the Better Auth
-- convention); the API maps them to uppercase at the DataStore boundary.
UPDATE "member" SET "role" = lower("role") WHERE "role" <> lower("role");
UPDATE "invitation" SET "role" = lower("role") WHERE "role" IS NOT NULL AND "role" <> lower("role");
