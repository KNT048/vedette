-- +goose Up
-- feeds_line_cve.only_builds: the builds of the product a line source's statement is limited to (a JSON array, "Oracle"), when the CVE is
-- in a part of the product only those builds ship (Oracle's installer, Java plugin, JavaFX in Java 8); NULL for every build. For another
-- build the statement says nothing. Written by applyLines (a JSON array of build names), read by LineData, which drops a cover whose
-- value does not read. Rows stored before have NULL until the source's next pull writes its statements again. Forward-only.
ALTER TABLE feeds_line_cve ADD COLUMN only_builds TEXT;
