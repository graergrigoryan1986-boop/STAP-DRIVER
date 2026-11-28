-- Preserve every order while repairing duplicate non-null order codes.
-- On older databases the column may not exist yet; Prisma db push creates it afterward.
DO $$
DECLARE
  duplicate_order RECORD;
  candidate_code INTEGER;
  attempts INTEGER;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'Order'
      AND column_name = 'orderCode'
  ) THEN
    FOR duplicate_order IN
      SELECT id
      FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                 PARTITION BY "orderCode"
                 ORDER BY "createdAt" ASC, id ASC
               ) AS duplicate_rank
        FROM "Order"
        WHERE "orderCode" IS NOT NULL
      ) ranked
      WHERE duplicate_rank > 1
    LOOP
      attempts := 0;
      LOOP
        candidate_code := 1000 + FLOOR(RANDOM() * 9000)::INTEGER;
        EXIT WHEN NOT EXISTS (
          SELECT 1 FROM "Order" WHERE "orderCode" = candidate_code
        );
        attempts := attempts + 1;
        IF attempts >= 10000 THEN
          RAISE EXCEPTION 'No unused four-digit order code remains; no order was deleted.';
        END IF;
      END LOOP;

      UPDATE "Order"
      SET "orderCode" = candidate_code
      WHERE id = duplicate_order.id;
    END LOOP;
  END IF;
END $$;
