package ru.itis.sysan.practic0.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import ru.itis.sysan.practic0.bc.BlockChain;
import ru.itis.sysan.practic0.bc.BlockModel;
import ru.itis.sysan.practic0.bc.DataModel;
import ru.itis.sysan.practic0.service.SignService;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.logging.Logger;

@Controller
public class BlockchainController {

    private static Logger log = Logger.getLogger(BlockchainUIController.class.getName());

    @GetMapping(value = "/practic0/addsolution")
    public void addsolution(HttpServletRequest request, HttpServletResponse response,
                               @RequestParam(value = "solution", required = false) String solution) {

        if (solution != null && solution.length() > 0) {

            ObjectMapper mapper = new ObjectMapper();
            try {
                DataModel dm = mapper.readValue(solution, DataModel.class);

                BlockModel prevBlock = BlockChain.chain.get(BlockChain.chain.size() - 1);
                SignService signService = new SignService();
                String prevHash = new String(Hex.encode(signService.getHash(prevBlock)));

                BlockModel blockModel = new BlockModel();
                blockModel.setData(dm);
                blockModel.setTs(new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SX").format(new Date()));

                blockModel.setPrevhash(prevHash);
                BlockChain.chain.add(blockModel);
                BlockChain.saveBlockChain();


            } catch (JsonProcessingException | NoSuchAlgorithmException | UnsupportedEncodingException e) {
                String resp = e.getMessage();
                try {
                    response.getOutputStream().write(resp.getBytes("UTF8"));
                } catch (IOException er) {
                    er.printStackTrace();
                }
                e.printStackTrace();
                return;
            }
        }

        String resp = "ok\n";
        try {
            response.getOutputStream().write(resp.getBytes("UTF8"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
