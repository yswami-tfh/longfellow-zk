Procedure for updating a circuit to ensure backwards compatibility.

## If the inputs and witnesses are the same, but the gates have changed

-- Produce a new set of hashes and add them to zk_spec. -- Checkin the files
into circuits/ circuits using circuitmaker. -- Ensure that the unit tests all
pass.

## If the inputs/witnesses have changed

-- In addition to the above, the code that produces the witness and fills it
into the Dense object must branch on the version to properly create the prover
and verifier parameters.
