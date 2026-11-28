-- Repair duplicate order codes only when the legacy database already has the column.
-- Use dynamic SQL so PostgreSQL never resolves "orderCode" on schemas where it is absent.
DO $$
DECLARE
  duplicate_order RECORD;
  candidate_code INTEGER;
  attempts INTEGER;
  code_exists BOOLEAN;
  orders_table TEXT := format('%I.%I', current_schema(), 'Order');
BEGIN
  IF to_regclass(orders_table) IS NOT NULL
     AND EXISTS (
       SELECT 1
       FROM information_schema.columns
       WHERE table_schema = current_schema()
         AND table_name = 'Order'
         AND column_name = 'orderCode'
     )
  THEN
    FOR duplicate_order IN EXECUTE format(
      'SELECT id
       FROM (
         SELECT id,
                ROW_NUMBER() OVER (
                  PARTITION BY "orderCode"
                  ORDER BY "createdAt" ASC, id ASC
                ) AS duplicate_rank
         FROM %s
         WHERE "orderCode" IS NOT NULL
       ) ranked
       WHERE duplicate_rank > 1',
      orders_table
    )
    LOOP
      attempts := 0;
      LOOP
        candidate_code := 1000 + FLOOR(RANDOM() * 9000)::INTEGER;
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s WHERE "orderCode" = $1)', orders_table)
          INTO code_exists
          USING candidate_code;
        EXIT WHEN NOT code_exists;

        attempts := attempts + 1;
        IF attempts >= 10000 THEN
          RAISE EXCEPTION 'No unused four-digit order code remains; no order was deleted.';
        END IF;
      END LOOP;

      EXECUTE format('UPDATE %s SET "orderCode" = $1 WHERE id = $2', orders_table)
        USING candidate_code, duplicate_order.id;
    END LOOP;
  END IF;
END $$;
