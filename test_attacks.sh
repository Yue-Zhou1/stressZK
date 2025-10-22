#!/usr/bin/env bash
#
# Sequential zkarnage Attack Testing - One by One
# For precise research data collection with isolated measurements
#

set -e

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}🔬 zkarnage Sequential Attack Testing - Research Mode${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "This script will help you test each attack individually for precise"
echo "cycle count measurements. Each attack will be in its own batch."
echo ""

# Check if we're in zkarnage directory
if [ ! -f "foundry.toml" ]; then
    echo -e "${RED}❌ Not in zkarnage directory. Please cd to zkarnage first.${NC}"
    exit 1
fi

# Load .env
if [ -f ".env" ]; then
    source .env
fi

# Network configuration
TAIKO_HOODI_RPC="https://rpc.hoodi.taiko.xyz"
TAIKO_HOODI_CHAIN_ID=167013

# Check private key
if [ -z "$PRIVATE_KEY" ]; then
    echo -e "${RED}❌ PRIVATE_KEY not set in .env${NC}"
    exit 1
fi

# Create results file with timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="research_results_${TIMESTAMP}.csv"
NOTES_FILE="research_notes_${TIMESTAMP}.txt"

echo "# zkarnage Research Data - ${TIMESTAMP}" > $NOTES_FILE
echo "# One attack per batch for isolated measurements" >> $NOTES_FILE
echo "" >> $NOTES_FILE

# Create CSV with headers
echo "attack_num,attack_name,expected_cycles_per_gas,tx_hash,l2_block,gas_used,batch_id,l1_block,zk_cycles,actual_cycles_per_gas,prove_time_mins,notes" > $RESULTS_FILE

echo -e "${GREEN}✅ Results will be saved to:${NC}"
echo "   Data: $RESULTS_FILE"
echo "   Notes: $NOTES_FILE"
echo ""

# Check for existing contract or deploy
if [ -f ".env.taiko_hoodi" ]; then
    source .env.taiko_hoodi
fi

if [ -n "$STRESS_CONTRACT_ADDRESS" ]; then
    echo -e "${GREEN}✅ Using existing contract: ${STRESS_CONTRACT_ADDRESS}${NC}"
    CONTRACT_ADDRESS=$STRESS_CONTRACT_ADDRESS
else
    echo -e "${YELLOW}📤 Deploying ZKarnage contract...${NC}"
    DEPLOY_OUTPUT=$(forge script script/DeployZKarnage.s.sol \
        --rpc-url $TAIKO_HOODI_RPC \
        --broadcast \
        --legacy \
        2>&1)

    # Extract contract address from deployment output
    # forge script outputs the address in a log line like: "ZKarnage contract deployed at: 0x..."
    CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep "ZKarnage contract deployed at:" | awk '{print $NF}')

    if [ -z "$CONTRACT_ADDRESS" ]; then
        echo -e "${RED}❌ Failed to deploy contract${NC}"
        echo -e "${RED}Deployment output:${NC}"
        echo "$DEPLOY_OUTPUT"
        exit 1
    fi

    echo "STRESS_CONTRACT_ADDRESS=$CONTRACT_ADDRESS" > .env.taiko_hoodi
    echo -e "${GREEN}✅ Contract deployed: ${CONTRACT_ADDRESS}${NC}"
fi

echo ""
echo "Contract Address: $CONTRACT_ADDRESS" | tee -a $NOTES_FILE
echo "" | tee -a $NOTES_FILE

# Attack definitions with metadata
declare -A ATTACK_NAMES
declare -A ATTACK_EXPECTED_RATIO
declare -A ATTACK_DESCRIPTION
declare -A ATTACK_PARAMS

ATTACK_NAMES[1]="executeJumpdestAttack"
ATTACK_EXPECTED_RATIO[1]="1037.68"
ATTACK_DESCRIPTION[1]="Control flow (JUMPDEST) - HIGHEST cycles/gas ratio"
ATTACK_PARAMS[1]="iterations:uint256"

ATTACK_NAMES[2]="executeMcopyAttack"
ATTACK_EXPECTED_RATIO[2]="666.39"
ATTACK_DESCRIPTION[2]="Memory operations (MCOPY) - 2nd highest ratio"
ATTACK_PARAMS[2]="size:uint256,iterations:uint256"

ATTACK_NAMES[3]="executeCalldatacopyAttack"
ATTACK_EXPECTED_RATIO[3]="580.81"
ATTACK_DESCRIPTION[3]="Data copying (CALLDATACOPY) - 3rd highest ratio"
ATTACK_PARAMS[3]="size:uint256,iterations:uint256"

ATTACK_NAMES[4]="executeBnPairingAttack"
ATTACK_EXPECTED_RATIO[4]="37.91"
ATTACK_DESCRIPTION[4]="BN254 Pairing precompile - Most expensive precompile"
ATTACK_PARAMS[4]="iterations:uint256"

ATTACK_NAMES[5]="executeBnMulAttack"
ATTACK_EXPECTED_RATIO[5]="17.48"
ATTACK_DESCRIPTION[5]="BN254 Multiplication precompile"
ATTACK_PARAMS[5]="iterations:uint256"

ATTACK_NAMES[6]="executeEcrecoverAttack"
ATTACK_EXPECTED_RATIO[6]="15.74"
ATTACK_DESCRIPTION[6]="ECRECOVER signature recovery precompile"
ATTACK_PARAMS[6]="iterations:uint256"

ATTACK_NAMES[7]="executeModExpAttack"
ATTACK_EXPECTED_RATIO[7]="Variable"
ATTACK_DESCRIPTION[7]="Modular exponentiation precompile"
ATTACK_PARAMS[7]="iterations:uint256"

ATTACK_NAMES[8]="executeAttack"
ATTACK_EXPECTED_RATIO[8]="Baseline"
ATTACK_DESCRIPTION[8]="Original EXTCODESIZE attack - Baseline"
ATTACK_PARAMS[8]="targets:address[]"

# Total number of attacks
TOTAL_ATTACKS=8

# Function to execute and record an attack
execute_attack() {
    local num=$1
    local attack_name=${ATTACK_NAMES[$num]}
    local expected_ratio=${ATTACK_EXPECTED_RATIO[$num]}
    local description=${ATTACK_DESCRIPTION[$num]}

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}Attack ${num}/${TOTAL_ATTACKS}: ${attack_name}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BLUE}Description:${NC} $description"
    echo -e "${BLUE}Expected Cycles/Gas:${NC} $expected_ratio"
    echo ""

    # Get attack parameters
    local params=${ATTACK_PARAMS[$num]}
    local param_values=""
    local function_sig="${attack_name}("

    if [[ "$params" == "iterations:uint256" ]]; then
        echo -e "${YELLOW}This attack requires an iteration count parameter.${NC}"
        read -p "Enter number of iterations (e.g., 10, 100, 1000): " iterations
        param_values="$iterations"
        function_sig="${function_sig}uint256)"
    elif [[ "$params" == "size:uint256,iterations:uint256" ]]; then
        echo -e "${YELLOW}This attack requires size and iteration parameters.${NC}"
        read -p "Enter size (e.g., 1024, 4096): " size
        read -p "Enter number of iterations (e.g., 10, 100): " iterations
        param_values="$size $iterations"
        function_sig="${function_sig}uint256,uint256)"
    elif [[ "$params" == "targets:address[]" ]]; then
        echo -e "${YELLOW}This attack requires an array of target addresses.${NC}"
        echo -e "${YELLOW}For simplicity, using contract itself as target.${NC}"
        param_values="[$CONTRACT_ADDRESS]"
        function_sig="${function_sig}address[])"
    else
        function_sig="${function_sig})"
    fi

    echo ""

    # Confirm execution
    read -p "Execute this attack? [Y/n]: " confirm
    confirm=${confirm:-Y}
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}⏭️  Skipped${NC}"
        return
    fi

    # Execute the attack
    echo ""
    echo -e "${YELLOW}📤 Executing ${attack_name}(${param_values})...${NC}"
    TX_OUTPUT=$(cast send $CONTRACT_ADDRESS "${function_sig}" $param_values \
        --rpc-url $TAIKO_HOODI_RPC \
        --private-key $PRIVATE_KEY \
        --legacy \
        2>&1)

    # Extract transaction hash from cast send output
    # It can be either a standalone line "0x..." or a line "transactionHash    0x..."
    TX_HASH=$(echo "$TX_OUTPUT" | grep -oE "0x[a-fA-F0-9]{64}" | tail -n 1)

    if [ -z "$TX_HASH" ]; then
        echo -e "${RED}❌ Failed to execute attack${NC}"
        echo -e "${RED}Output:${NC}"
        echo "$TX_OUTPUT"
        echo "$num,$attack_name,$expected_ratio,FAILED,,,,,,,Failed to execute" >> $RESULTS_FILE
        return
    fi

    echo -e "${GREEN}✅ Transaction sent: ${TX_HASH}${NC}"

    # Check if TX_OUTPUT already contains receipt data (cast send with --legacy shows receipt)
    if echo "$TX_OUTPUT" | grep -q "blockNumber"; then
        echo "⏳ Parsing transaction receipt..."
        # Extract from the cast send output
        L2_BLOCK=$(echo "$TX_OUTPUT" | grep "^blockNumber" | awk '{print $2}' | xargs printf "%d\n" 2>/dev/null || echo "unknown")
        GAS_USED=$(echo "$TX_OUTPUT" | grep "^gasUsed" | awk '{print $2}' | xargs printf "%d\n" 2>/dev/null || echo "unknown")
        STATUS=$(echo "$TX_OUTPUT" | grep "^status" | awk '{print $2}' | cut -d' ' -f1)
    else
        # Wait for receipt if not already in output
        echo "⏳ Waiting for transaction confirmation..."
        sleep 5

        # Get receipt
        RECEIPT=$(cast receipt $TX_HASH --rpc-url $TAIKO_HOODI_RPC -j 2>/dev/null)

        if [ -z "$RECEIPT" ]; then
            echo -e "${YELLOW}⚠️  Could not get receipt immediately. Waiting longer...${NC}"
            sleep 10
            RECEIPT=$(cast receipt $TX_HASH --rpc-url $TAIKO_HOODI_RPC -j 2>/dev/null)
        fi

        # Extract data
        L2_BLOCK=$(echo "$RECEIPT" | jq -r '.blockNumber' | xargs printf "%d\n" 2>/dev/null || echo "unknown")
        GAS_USED=$(echo "$RECEIPT" | jq -r '.gasUsed' | xargs printf "%d\n" 2>/dev/null || echo "unknown")
        STATUS=$(echo "$RECEIPT" | jq -r '.status' 2>/dev/null || echo "unknown")
    fi

    echo ""
    echo -e "${GREEN}📊 Transaction Details:${NC}"
    echo "   Transaction Hash: $TX_HASH"
    echo "   L2 Block Number:  $L2_BLOCK"
    echo "   Gas Used:         $GAS_USED"
    echo "   Status:           $STATUS"
    echo ""

    # Save to notes
    echo "═══════════════════════════════════════════════════════" >> $NOTES_FILE
    echo "Attack $num: $attack_name" >> $NOTES_FILE
    echo "═══════════════════════════════════════════════════════" >> $NOTES_FILE
    echo "Expected cycles/gas: $expected_ratio" >> $NOTES_FILE
    echo "Parameters: $param_values" >> $NOTES_FILE
    echo "Transaction: $TX_HASH" >> $NOTES_FILE
    echo "L2 Block: $L2_BLOCK" >> $NOTES_FILE
    echo "Gas Used: $GAS_USED" >> $NOTES_FILE
    echo "" >> $NOTES_FILE

    # Instructions for proving
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}📋 Next Steps - Proving this Attack${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${YELLOW}1. Wait 15-20 minutes for L2 block to be batched${NC}"
    echo ""
    echo -e "${YELLOW}2. Find which batch contains L2 block ${L2_BLOCK}:${NC}"
    echo -e "   ${GREEN}cd ../raiko${NC}"
    echo -e "   ${GREEN}python3 script/find_batch_containing_l2_block.py ${L2_BLOCK}${NC}"
    echo ""
    echo -e "${YELLOW}3. Note the batch ID and L1 block number from output${NC}"
    echo ""
    echo -e "${YELLOW}4. Prove the batch:${NC}"
    echo -e "   ${GREEN}./script/prove_batch_get_cycles.sh <BATCH_ID> <L1_BLOCK>${NC}"
    echo ""
    echo -e "${YELLOW}5. Record the cycle count from proving logs${NC}"
    echo "   Look for lines mentioning 'cycles' or 'segments'"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
    echo ""

    # Prompt for proving results
    echo -e "${BLUE}After proving, please enter the results:${NC}"
    echo ""

    read -p "Batch ID (from step 2): " BATCH_ID
    read -p "L1 Block Number (from step 2): " L1_BLOCK
    read -p "Total ZK Cycles (from proving logs): " ZK_CYCLES
    read -p "Prove Time in minutes: " PROVE_TIME
    read -p "Any notes/observations: " USER_NOTES

    # Calculate actual ratio
    if [[ "$GAS_USED" != "unknown" ]] && [[ "$ZK_CYCLES" =~ ^[0-9]+$ ]]; then
        ACTUAL_RATIO=$(echo "scale=2; $ZK_CYCLES / $GAS_USED" | bc)
    else
        ACTUAL_RATIO="N/A"
    fi

    # Save to CSV
    echo "$num,$attack_name,$expected_ratio,$TX_HASH,$L2_BLOCK,$GAS_USED,$BATCH_ID,$L1_BLOCK,$ZK_CYCLES,$ACTUAL_RATIO,$PROVE_TIME,\"$USER_NOTES\"" >> $RESULTS_FILE

    # Save to notes
    echo "Batch ID: $BATCH_ID" >> $NOTES_FILE
    echo "L1 Block: $L1_BLOCK" >> $NOTES_FILE
    echo "ZK Cycles: $ZK_CYCLES" >> $NOTES_FILE
    echo "Actual cycles/gas: $ACTUAL_RATIO" >> $NOTES_FILE
    echo "Prove Time: $PROVE_TIME minutes" >> $NOTES_FILE
    echo "Notes: $USER_NOTES" >> $NOTES_FILE
    echo "" >> $NOTES_FILE

    echo ""
    echo -e "${GREEN}✅ Attack $num recorded successfully!${NC}"
    echo ""

    # Summary
    echo -e "${BLUE}Quick Summary:${NC}"
    echo "   Expected ratio: $expected_ratio"
    echo "   Actual ratio:   $ACTUAL_RATIO"
    if [[ "$expected_ratio" != "Baseline" ]] && [[ "$expected_ratio" != "Variable" ]]; then
        if [[ "$ACTUAL_RATIO" != "N/A" ]]; then
            DIFF=$(echo "scale=2; $ACTUAL_RATIO - $expected_ratio" | bc)
            echo "   Difference:     $DIFF"
        fi
    fi
    echo ""

    # Ask if ready for next
    if [ $num -lt $TOTAL_ATTACKS ]; then
        echo -e "${CYAN}Press Enter when ready for the next attack...${NC}"
        read
    fi
}

# Main execution loop
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}Starting Sequential Attack Testing${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "You can stop at any time with Ctrl+C"
echo "Progress is saved after each attack"
echo ""

# Ask if user wants to start from a specific attack
read -p "Start from attack number (1-8, or press Enter for 1): " START_NUM
START_NUM=${START_NUM:-1}

if ! [[ "$START_NUM" =~ ^[1-8]$ ]]; then
    echo -e "${RED}Invalid attack number. Starting from 1.${NC}"
    START_NUM=1
fi

if [ "$START_NUM" -gt 1 ]; then
    echo -e "${YELLOW}Starting from attack $START_NUM, skipping attacks 1-$((START_NUM-1))${NC}"
    echo ""
fi

# Execute all attacks
for i in $(seq $START_NUM 8); do
    execute_attack $i
done

# Final summary
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ All Attacks Completed!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${BLUE}Results saved to:${NC}"
echo "   📊 CSV Data: $RESULTS_FILE"
echo "   📝 Notes:    $NOTES_FILE"
echo ""
echo -e "${BLUE}You can now analyze your data:${NC}"
echo "   cat $RESULTS_FILE | column -t -s,"
echo ""
echo -e "${CYAN}Thank you for your patience! Good luck with your research! 🚀${NC}"
echo ""
